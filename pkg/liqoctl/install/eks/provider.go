package eks

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/iam"
	flag "github.com/spf13/pflag"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/liqotech/liqo/pkg/liqoctl/install/provider"
)

const (
	providerPrefix = "eks"
)

type eksProvider struct {
	region      string
	clusterName string

	endpoint    string
	serviceCIDR string
	podCIDR     string

	iamLiqoUser iamLiqoUser
}

type iamLiqoUser struct {
	userName   string
	policyName string

	accessKeyID     string
	secretAccessKey string
}

// NewProvider initializes a new EKS provider struct.
func NewProvider() provider.InstallProviderInterface {
	return &eksProvider{}
}

// ValidateCommandArguments validates specific arguments passed to the install command.
func (k *eksProvider) ValidateCommandArguments(flags *flag.FlagSet) (err error) {
	k.region, err = flags.GetString(prefixedName("region"))
	if err != nil {
		return err
	}
	if k.region == "" {
		err := fmt.Errorf("--eks.region not provided")
		return err
	}
	klog.V(3).Infof("EKS Region: %v", k.region)

	k.clusterName, err = flags.GetString(prefixedName("cluster-name"))
	if err != nil {
		return err
	}
	if k.clusterName == "" {
		err := fmt.Errorf("--eks.cluster-name not provided")
		return err
	}
	klog.V(3).Infof("EKS ClusterName: %v", k.clusterName)

	k.iamLiqoUser.userName, err = flags.GetString(prefixedName("user-name"))
	if err != nil {
		return err
	}
	if k.iamLiqoUser.userName == "" {
		err := fmt.Errorf("--eks.user-name not provided")
		return err
	}
	klog.V(3).Infof("Liqo IAM username: %v", k.iamLiqoUser.userName)

	k.iamLiqoUser.policyName, err = flags.GetString(prefixedName("policy-name"))
	if err != nil {
		return err
	}
	if k.iamLiqoUser.policyName == "" {
		err := fmt.Errorf("--eks.policy-name not provided")
		return err
	}
	klog.V(3).Infof("Liqo IAM policy name: %v", k.iamLiqoUser.policyName)

	// optional values

	k.iamLiqoUser.accessKeyID, err = flags.GetString(prefixedName("access-key-id"))
	if err != nil {
		return err
	}

	k.iamLiqoUser.secretAccessKey, err = flags.GetString(prefixedName("secret-access-key"))
	if err != nil {
		return err
	}

	return nil
}

// ExtractChartParameters fetches the parameters used to customize the Liqo installation on a specific cluster of a
// given provider.
func (k *eksProvider) ExtractChartParameters(ctx context.Context, _ *rest.Config) error {
	sess, err := session.NewSession()
	if err != nil {
		return err
	}

	if err = k.getClusterInfo(sess); err != nil {
		return err
	}

	if err = k.createIamIdentity(sess); err != nil {
		return err
	}

	return nil
}

// UpdateChartValues patches the values map with the values required for the selected cluster.
func (k *eksProvider) UpdateChartValues(values map[string]interface{}) {
	values["apiServer"] = map[string]interface{}{
		"address": k.endpoint,
	}
	values["networkManager"] = map[string]interface{}{
		"config": map[string]interface{}{
			"serviceCIDR": k.serviceCIDR,
			"podCIDR":     k.podCIDR,
		},
	}
	values["awsConfig"] = map[string]interface{}{
		"accessKeyId":     k.iamLiqoUser.accessKeyID,
		"secretAccessKey": k.iamLiqoUser.secretAccessKey,
		"region":          k.region,
		"clusterName":     k.clusterName,
	}
}

// GenerateFlags generates the set of specific subpath and flags are accepted for a specific provider.
func GenerateFlags(flags *flag.FlagSet) {
	subFlag := flag.NewFlagSet(providerPrefix, flag.ExitOnError)
	subFlag.SetNormalizeFunc(func(f *flag.FlagSet, name string) flag.NormalizedName {
		return flag.NormalizedName(prefixedName(name))
	})

	subFlag.String("region", "", "The EKS region where your cluster is running")
	subFlag.String("cluster-name", "", "The EKS clusterName of your cluster")

	subFlag.String("user-name", "", "The username to assign to the Liqo user")
	subFlag.String("policy-name", "", "The name of the policy to assign to the Liqo user")

	subFlag.String("access-key-id", "", "The IAM accessKeyID for the Liqo user (optional)")
	subFlag.String("secret-access-key", "", "The IAM secretAccessKey for the Liqo user (optional)")

	flags.AddFlagSet(subFlag)
}

// getClusterInfo retrieved information from the EKS cluster.
func (k *eksProvider) getClusterInfo(sess *session.Session) error {
	eksSvc := eks.New(sess, aws.NewConfig().WithRegion(k.region))

	describeCluster := &eks.DescribeClusterInput{
		Name: aws.String(k.clusterName),
	}

	describeClusterResult, err := eksSvc.DescribeCluster(describeCluster)
	if err != nil {
		return err
	}

	if err = k.parseClusterOutput(describeClusterResult); err != nil {
		return err
	}

	if describeClusterResult.Cluster.ResourcesVpcConfig.VpcId == nil {
		err := fmt.Errorf("the EKS cluster %v in region %v does not have a valid VPC ID", k.clusterName, k.region)
		return err
	}
	vpcID := *describeClusterResult.Cluster.ResourcesVpcConfig.VpcId

	ec2Svc := ec2.New(sess, aws.NewConfig().WithRegion(k.region))

	describeVpc := &ec2.DescribeVpcsInput{
		VpcIds: aws.StringSlice([]string{vpcID}),
	}

	describeVpcResult, err := ec2Svc.DescribeVpcs(describeVpc)
	if err != nil {
		return err
	}

	if err = k.parseVpcOutput(vpcID, describeVpcResult); err != nil {
		return err
	}

	return nil
}

func (k *eksProvider) parseClusterOutput(describeClusterResult *eks.DescribeClusterOutput) error {
	if describeClusterResult.Cluster.Endpoint == nil {
		err := fmt.Errorf("the EKS cluster %v in region %v does not have a valid endpoint", k.clusterName, k.region)
		return err
	}
	k.endpoint = *describeClusterResult.Cluster.Endpoint

	if describeClusterResult.Cluster.KubernetesNetworkConfig.ServiceIpv4Cidr == nil {
		err := fmt.Errorf("the EKS cluster %v in region %v does not have a valid service CIDR", k.clusterName, k.region)
		return err
	}
	k.serviceCIDR = *describeClusterResult.Cluster.KubernetesNetworkConfig.ServiceIpv4Cidr

	return nil
}

func (k *eksProvider) parseVpcOutput(vpcID string, describeVpcResult *ec2.DescribeVpcsOutput) error {
	vpcs := describeVpcResult.Vpcs
	switch len(vpcs) {
	case 1:
		break
	case 0:
		err := fmt.Errorf("no VPC found with id %v", vpcID)
		return err
	default:
		err := fmt.Errorf("multiple VPC found with id %v", vpcID)
		return err
	}
	k.podCIDR = *vpcs[0].CidrBlock

	return nil
}

// createIamIdentity crates the Liqo IAM user identity.
func (k *eksProvider) createIamIdentity(sess *session.Session) error {
	iamSvc := iam.New(sess, aws.NewConfig().WithRegion(k.region))

	if err := k.ensureUser(iamSvc); err != nil {
		return err
	}

	policyArn, err := k.ensurePolicy(iamSvc)
	if err != nil {
		return err
	}

	attachUserPolicyRequest := &iam.AttachUserPolicyInput{
		PolicyArn: aws.String(policyArn),
		UserName:  aws.String(k.iamLiqoUser.userName),
	}

	_, err = iamSvc.AttachUserPolicy(attachUserPolicyRequest)
	if err != nil {
		return err
	}

	return nil
}

func (k *eksProvider) requiresUserCreation() bool {
	return k.iamLiqoUser.accessKeyID == "" || k.iamLiqoUser.secretAccessKey == ""
}

func (k *eksProvider) ensureUser(iamSvc *iam.IAM) error {
	if !k.requiresUserCreation() {
		klog.V(3).Info("Using provided IAM credentials")
		return nil
	}

	createUserRequest := &iam.CreateUserInput{
		UserName: aws.String(k.iamLiqoUser.userName),
	}

	_, err := iamSvc.CreateUser(createUserRequest)
	if err != nil {
		return err
	}

	createAccessKeyRequest := &iam.CreateAccessKeyInput{
		UserName: aws.String(k.iamLiqoUser.userName),
	}

	createAccessKeyResult, err := iamSvc.CreateAccessKey(createAccessKeyRequest)
	if err != nil {
		return err
	}

	k.iamLiqoUser.accessKeyID = *createAccessKeyResult.AccessKey.AccessKeyId
	k.iamLiqoUser.secretAccessKey = *createAccessKeyResult.AccessKey.SecretAccessKey

	return nil
}

func (k *eksProvider) ensurePolicy(iamSvc *iam.IAM) (string, error) {
	policyDocument, err := getPolicyDocument()
	if err != nil {
		return "", err
	}

	createPolicyRequest := &iam.CreatePolicyInput{
		PolicyName:     aws.String(k.iamLiqoUser.policyName),
		PolicyDocument: aws.String(policyDocument),
	}

	createPolicyResult, err := iamSvc.CreatePolicy(createPolicyRequest)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok { // nolint:errorlint // we need to access methods of the aws error interface
			switch aerr.Code() {
			case iam.ErrCodeEntityAlreadyExistsException:
				return k.checkPolicy(iamSvc)
			default:
				return "", err
			}
		} else {
			// not an AWS error
			return "", err
		}
	}

	return *createPolicyResult.Policy.Arn, nil
}

func (k *eksProvider) getPolicyArn(iamSvc *iam.IAM) (string, error) {
	getUserResult, err := iamSvc.GetUser(&iam.GetUserInput{})
	if err != nil {
		return "", err
	}

	splits := strings.Split(*getUserResult.User.Arn, ":")
	accountID := splits[4]

	return fmt.Sprintf("arn:aws:iam::%v:policy/%v", accountID, k.iamLiqoUser.policyName), nil
}

// checkPolicy checks that the retrieved policy has the required permission.
func (k *eksProvider) checkPolicy(iamSvc *iam.IAM) (string, error) {
	arn, err := k.getPolicyArn(iamSvc)
	if err != nil {
		return "", err
	}

	getPolicyRequest := &iam.GetPolicyInput{
		PolicyArn: aws.String(arn),
	}

	getPolicyResult, err := iamSvc.GetPolicy(getPolicyRequest)
	if err != nil {
		return "", err
	}
	defaultVersionID := getPolicyResult.Policy.DefaultVersionId

	getPolicyVersionRequest := &iam.GetPolicyVersionInput{
		PolicyArn: aws.String(arn),
		VersionId: defaultVersionID,
	}

	getPolicyVersionResult, err := iamSvc.GetPolicyVersion(getPolicyVersionRequest)
	if err != nil {
		return "", err
	}

	policyDocument, err := getPolicyDocument()
	if err != nil {
		return "", err
	}

	tmp, err := url.QueryUnescape(*getPolicyVersionResult.PolicyVersion.Document)
	if err != nil {
		return "", err
	}

	if tmp != policyDocument {
		return "", fmt.Errorf("the %v IAM policy has not the permission required by Liqo",
			k.iamLiqoUser.policyName)
	}

	return arn, nil
}

func prefixedName(name string) string {
	return fmt.Sprintf("%v.%v", providerPrefix, name)
}
