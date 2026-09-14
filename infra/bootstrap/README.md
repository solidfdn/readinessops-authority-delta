# Bootstrap deployment service

Recovery R1 replaces the unsupported root-to-Role path with an AWS CodeBuild service.
The existing `authority-delta-bootstrap` stack and `ReadinessOpsAuthorityDeltaDeployer`
role are updated in place. The role is trusted only by `codebuild.amazonaws.com` for
the `authority-delta-deploy` project in the same account and Region.

CloudShell, currently authenticated as root, verifies account MFA and the budget,
updates the bootstrap stack, uploads an immutable source version, starts the build and
reads its result. The application deployment and DynamoDB seed happen inside CodeBuild.
No root credentials are forwarded to CodeBuild. No IAM user, access key, login password
or manual role switch is introduced.

CodeBuild uses `aws/codebuild/standard:7.0`, Python 3.12, one concurrent build, a 25-minute
build limit and a five-minute queue limit. It has no webhook or schedule. Build logs
expire after 14 days. The private versioned S3 bucket retains source, artifacts and
evidence. Build execution is metered; the existing USD 50 budget remains a notification
threshold, not an automatic spending cap.

PowerUserAccess remains a hackathon deployment-role compromise, with IAM management
and PassRole restricted to project workload roles. It is not a least-privilege production
deployment policy. Application identities retain their scoped permissions.

To stop a running deployment, use CodeBuild's Stop build control for the printed build
ID. Stopping a build does not cancel an already-started CloudFormation operation or
delete application resources. There is no idle build worker to stop after completion.
Application tables and the artifact bucket have Retain policies; preserve audit evidence
when performing later cleanup.
