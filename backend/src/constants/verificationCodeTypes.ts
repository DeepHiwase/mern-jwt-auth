/**
 * Instead of reguler enums we are using const enums which when compile to js replaces/injects
 *  the EmailVerification with 'email_verification' instead
 * of creating the enum object with keys-values and referencing the values
 * in the code, but i think its also not good idea to use const enums
 */

const enum VerificationCodeTypes {
  EmailVerification = "email_verification",
  PasswordReset = "password_reset",
}

export default VerificationCodeTypes;
