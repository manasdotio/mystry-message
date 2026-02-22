import { resend } from "@/lib/resend";
import VerificationEmail from "../../emails/VerificationEmail";
import { ApiResponse } from "@/types/ApiResponse";

export async function sendVerificationEmail(
  email: string,
  username: string,
  verifyCode: string,
): Promise<ApiResponse> {
  try {
    if (!process.env.RESEND_API_KEY) {
      return {
        success: false,
        message: "Email service is not configured (missing RESEND_API_KEY)",
      };
    }

    const { error } = await resend.emails.send({
      from: process.env.RESEND_FROM_EMAIL || "onboarding@resend.dev",
      to: email,
      subject: "Mystry message|Verification code",
      react: VerificationEmail({ username, otp: verifyCode }),
    });

    if (error) {
      return {
        success: false,
        message: error.message || "Failed to send verification email",
      };
    }

    return {
      success: true,
      message: "Verification email sent successfully",
    };
  } catch (emailError) {
    console.error("Failed to send verification email", emailError);
    return {
      success: false,
      message: "Failed to send verification email",
    };
  }
}
