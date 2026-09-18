import { defineAuth } from '@aws-amplify/backend';

/**
 * Cognito auth for the console.
 *
 * defineAuth provisions a User Pool (sign-in) and an Identity Pool (which
 * exchanges the signed-in user's token for temporary AWS credentials). The
 * browser uses those temporary credentials to invoke the Flow agent directly;
 * there is no backend server in between.
 *
 * Email sign-in only, and self sign-up is disabled: for a demo you create the
 * user(s) yourself in the Cognito console (or with the CLI). MFA and a stricter
 * password policy can be turned on here later without touching the frontend.
 */
export const auth = defineAuth({
  loginWith: {
    email: true,
  },
});
