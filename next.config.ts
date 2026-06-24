import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },


  experimental: {
    serverComponentsExternalPackages: [
      '@xenova/transformers',
      'onnxruntime-node',
      'sharp',
    ],
  },

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
