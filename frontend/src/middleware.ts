import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const token = request.cookies.get('auth_token')?.value;

  if (!token) {
    const signInUrl = new URL('/auth/signin', request.url);
    signInUrl.searchParams.set('from', request.nextUrl.pathname);
    return NextResponse.redirect(signInUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*', '/admin/:path*', '/viewer/:path*'],
};
