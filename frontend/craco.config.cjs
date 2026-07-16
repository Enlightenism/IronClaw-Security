// craco.config.js
const path = require("path");

// Anchor dotenv to frontend/ regardless of where the command is run from
require("dotenv").config({ path: path.resolve(__dirname, ".env") });

// Check if we're in development/preview mode (not production build)
const isDevServer = process.env.NODE_ENV !== "production";

// Environment variable overrides
const config = {
  enableHealthCheck: process.env.ENABLE_HEALTH_CHECK === "true",
};

// Conditionally load health check modules only if enabled
let WebpackHealthPlugin;
let setupHealthEndpoints;
let healthPluginInstance;

if (config.enableHealthCheck) {
  WebpackHealthPlugin = require("./plugins/health-check/webpack-health-plugin");
  setupHealthEndpoints = require("./plugins/health-check/health-endpoints");
  healthPluginInstance = new WebpackHealthPlugin();
}

let webpackConfig = {
  eslint: {
    pluginOptions: {
      failOnError: false,
    },
    configure: {
      extends: ["plugin:react-hooks/recommended"],
      rules: {
        "react-hooks/rules-of-hooks": "error",
        "react-hooks/exhaustive-deps": "warn",
      },
    },
  },
  webpack: {
    alias: {
      "@": path.resolve(__dirname, "src"),
    },
    configure: (webpackConfig) => {
      webpackConfig.watchOptions = {
        ...webpackConfig.watchOptions,
        ignored: [
          "**/node_modules/**",
          "**/.git/**",
          "**/build/**",
          "**/dist/**",
          "**/coverage/**",
          "**/public/**",
        ],
      };

      webpackConfig.optimization = {
        ...webpackConfig.optimization,
        runtimeChunk: "single",
        splitChunks: {
          ...webpackConfig.optimization?.splitChunks,
          chunks: "all",
          maxInitialRequests: 25,
          minSize: 20000,
          cacheGroups: {
            ...webpackConfig.optimization?.splitChunks?.cacheGroups,
            reactVendor: {
              test: /[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/,
              name: "react-vendor",
              chunks: "all",
              priority: 40,
              enforce: true,
              reuseExistingChunk: true,
            },
            queryVendor: {
              test: /[\\/]node_modules[\\/]@tanstack[\\/]/,
              name: "query-vendor",
              chunks: "all",
              priority: 35,
              enforce: true,
              reuseExistingChunk: true,
            },
            supabaseVendor: {
              test: /[\\/]node_modules[\\/]@supabase[\\/]/,
              name: "supabase-vendor",
              chunks: "all",
              priority: 30,
              enforce: true,
              reuseExistingChunk: true,
            },
            uiVendor: {
              test: /[\\/]node_modules[\\/](@radix-ui|lucide-react|framer-motion|recharts|embla-carousel-react|cmdk|vaul)[\\/]/,
              name: "ui-vendor",
              chunks: "all",
              priority: 25,
              enforce: true,
              reuseExistingChunk: true,
            },
            vendor: {
              test: /[\\/]node_modules[\\/]/,
              name: "vendor",
              chunks: "all",
              priority: 10,
              reuseExistingChunk: true,
            },
          },
        },
      };

      if (config.enableHealthCheck && healthPluginInstance) {
        webpackConfig.plugins.push(healthPluginInstance);
      }

      return webpackConfig;
    },
  },
  jest: {
    configure: {
      moduleNameMapper: {
        "^@/(.*)$": "<rootDir>/src/$1",
      },
    },
  },
};

webpackConfig.devServer = (devServerConfig) => {
  if (config.enableHealthCheck && setupHealthEndpoints && healthPluginInstance) {
    const originalSetupMiddlewares = devServerConfig.setupMiddlewares;

    devServerConfig.setupMiddlewares = (middlewares, devServer) => {
      if (originalSetupMiddlewares) {
        middlewares = originalSetupMiddlewares(middlewares, devServer);
      }
      setupHealthEndpoints(devServer, healthPluginInstance);
      return middlewares;
    };
  }

  return devServerConfig;
};

if (isDevServer) {
  try {
    const { withVisualEdits } = require("@emergentbase/visual-edits/craco");
    webpackConfig = withVisualEdits(webpackConfig);
  } catch (err) {
    if (
      err.code === "MODULE_NOT_FOUND" &&
      err.message.includes("@emergentbase/visual-edits/craco")
    ) {
      console.warn(
        "[visual-edits] @emergentbase/visual-edits not installed — visual editing disabled.",
      );
    } else {
      throw err;
    }
  }
}

module.exports = webpackConfig;
