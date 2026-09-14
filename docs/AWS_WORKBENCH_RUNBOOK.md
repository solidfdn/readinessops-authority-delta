# Authenticated review workbench

This is the next delivery after the user-reported Gate B V3 semantic PASS.
The frozen product, three decision meanings and two-account Gate C remain unchanged.

## Operator

Upload `Authority_Delta_Workbench.py` to CloudShell and run:

```bash
python3 ~/Authority_Delta_Workbench.py
```

The operator reuses the existing Verification V2 and Analysis Dependencies ZIPs.
It uses the existing account/CodeBuild service role. It does not rerun semantic
analysis, vendor replays, Gate A, bootstrap or Gateway policy tests.

One new stack, `authority-delta-workbench`, creates private S3 hosting behind
CloudFront, a Cognito reviewer pool, PKCE browser client, and a JWT-protected
read-only API. Only the fixed successful evidence version is readable by the
Lambda role. The static public assets contain no execution evidence or credentials.
The API route requires the custom read scope and the signed assigned username;
the Cognito subject remains the future approval identity. Self-registration is off.
The initial `okada` user is created with message delivery suppressed.

After the build succeeds, the operator asks for a password locally using hidden
input. It sends the password to the AWS CLI over stdin, never command arguments,
source, CodeBuild or evidence. A confirmed user's password is preserved. The URL
and username are printed after setup. Resume the saved build if the connection or
password setup is interrupted; do not restart deployment to recover its result.

## What this screen does

- Load actual validated semantic and benign proposals from the pinned successful
  report. Revalidate source, full case coverage, input digests and proposal binding.
- Show the one changed judgment with source references and actual definition values.
- Preview MAINTAIN, NARROW and REJECT using the existing deterministic boundary
  evaluator, including the auxiliary C-001 control outside the six-case count.
- Distinguish observed agent judgments from calculated policy effects.
- Export the review document with its source version and digest.

The preview does not record an approval, publish a policy or invoke a payment tool.
Those capabilities are still Gate C work. A delivery PASS is not a human sign-in,
UI acceptance or complete Gate B PASS. The actual browser login and review remain
pending until performed. SEM-03 completion must be checked against ACCEPTANCE
before promoting the full Gate B; local missing/invalid-input tests are retained.

## Delivery checks and cost/state

The worker validates deployed HTML/JS/CSS/config bytes over HTTPS and requires
401 from the unauthenticated review API. It compares the protected baseline
before and after and records failures without promoting gates. Its maximum build
window is 25 minutes, not an estimated completion time. Frontend assets are
precompiled locally; no npm download is needed in CloudShell or CodeBuild.

Existing USD 50 monthly notification budget remains. This is not a spending cap.
The new resources remain deployed for review; no background build is started here.
To retire this stage, disable its CloudFront distribution and remove its stack
through the normal owned-resource teardown. S3 evidence and the Cognito pool have
retention policies; do not delete them as an automatic failure recovery.

## Rebuild

```bash
cd workbench
npm ci --ignore-scripts
npm run build
```

Copy the three built assets and manifest to `services/workbench/assets/` before
committing and building the operator. React/React DOM and the build dependencies
are pinned in package-lock.json. Bundled license notices are retained.
Local UI tests use React server rendering and PKCE contract checks; they are not
browser or real AWS authentication tests. AWS worker tests use botocore Stubber.
The final delivery check restores the actual operator in a fresh directory and
runs its launcher through a CLI process double, including password stdin handling.

Sources checked 2026-09-09:
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html
- https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooluser.html
- https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html
- https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html
- https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html

## Password recovery, 2026-09-09

The supplied terminal excerpt confirms password setup was reached after successful
build/report/binding guards, but its CLI failure reason was suppressed. It does
not establish a password policy or IAM cause. Do not rerun successful deployment.
Upload `Authority_Delta_Workbench_SignIn_Recovery.py` and execute
`python3 ~/Authority_Delta_Workbench_SignIn_Recovery.py`. It only resumes the saved
completed build and sets the initial review password if still needed. Already
CONFIRMED users are preserved. If rejected, the only diagnostic to return is
`PASSWORD_SETUP_ERROR`; never request the password or full CLI stderr/debug output.
The revised command uses a seekable anonymous memory file and explicit JSON output;
this removes input/output configuration ambiguities without asserting either was
the original cause. Error categories are allowlisted, not raw service messages.
No credentials are sent to CodeBuild, saved to disk or included in process arguments.

### Superseding recovery V2: no temporary-directory dependency

V1 recovery failed before AWS because the old launch.json was absent. Its prior
instructions above are historical. The corrected command is
`python3 ~/Authority_Delta_Workbench_SignIn_V2.py`.
This one file includes all local code and reads only the fixed S3 version
`Qld5q0Clx65Y1ODuSsaby8n3HM9Fhfu5` of
`evidence/6df3ab24c122455a819c8d46e42a9bfd/workbench-result.json`, then checks the live
workbench stack/account/outputs. It does not use any previous local launch record,
source directory or dependency ZIP, start CodeBuild, or redeploy resources.
The only mutation is initial Cognito password setup when still required.
