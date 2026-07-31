import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },


  // Next.js 15: serverExternalPackages replaces experimental.serverComponentsExternalPackages
  serverExternalPackages: [
    '@xenova/transformers',
    'onnxruntime-node',
    'sharp',
    'tough-cookie',
    '@apidevtools/swagger-parser',
    'jsonwebtoken',
  ],

  turbopack: {
    resolveAlias: {
      // ✅ Alias native ONNX to web/WASM version
      "onnxruntime-node": "onnxruntime-web",
    },
  },

  webpack: (config, { isServer }) => {

    config.resolve.alias = {
      ...config.resolve.alias,
      "onnxruntime-node": false,
    };

    if (isServer) {

      config.externals = [
        ...(Array.isArray(config.externals) ? config.externals : []),
        'onnxruntime-node',
        '@xenova/transformers',
      ];
    }


    config.module = {
      ...config.module,
      rules: [
        ...(config.module?.rules || []),
        {
          test: /\.node$/,
          use: 'ignore-loader',
        },
      ],
    };

    return config;
  },
};

export default nextConfig;
