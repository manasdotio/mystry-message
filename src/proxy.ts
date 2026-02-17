import { NextRequest, NextResponse } from "next/server";
import { getToken } from "next-auth/jwt";

// This function will run for every request that matches the specified matcher in the config
export async function proxy(request: NextRequest) {

  // Get the token from the request using next-auth's getToken function
  const token = await getToken({ req: request });

  // Get the URL of the incoming request
  const url = request.nextUrl;

  // If the user is not authenticated, redirect to the sign-in page
  if (
    token &&
    (url.pathname.startsWith("/sign-in") ||
      url.pathname.startsWith("/sign-up") ||
      url.pathname.startsWith("/verify") ||
      url.pathname.startsWith("/"))
  ) {
    return NextResponse.redirect(new URL("/dashboard", request.url)); // Redirect authenticated users away from the sign-in page
  }
  // If the user is not authenticated and tries to access a protected route, redirect to the sign-in page
  if (!token && url.pathname.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/sign-in", request.url)); // Redirect unauthenticated users to the sign-in page
  }
}

// Alternatively, you can use a default export:
// export default function proxy(request: NextRequest) { ... }

export const config = {
  matcher: ["/sign-in", "/sign-up", "/", "/dashboard/:path*", "/verify/:path*"],
};
