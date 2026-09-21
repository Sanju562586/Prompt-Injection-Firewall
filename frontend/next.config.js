/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/dashboard/:path*',
        destination: 'http://localhost:8000/api/dashboard/:path*',
      },
      {
        source: '/v1/:path*',
        destination: 'http://localhost:8000/v1/:path*',
      },
      {
        source: '/health',
        destination: 'http://localhost:8000/health',
      },
    ];
  },
};

module.exports = nextConfig;
