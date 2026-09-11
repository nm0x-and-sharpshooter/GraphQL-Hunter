// @ts-check
const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

/** @type {(env: any, argv: { mode: string }) => import('webpack').Configuration} */
module.exports = (env, argv) => {
  const isDev = argv.mode === 'development';

  return {
    entry: {
      'background/background': './extension/background/background.ts',
      'popup/popup':           './extension/popup/popup.ts',
      'content/content':       './extension/content/content.ts',
      'content/page-hook':     './extension/content/page-hook.ts',
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
      clean: true,
    },
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: {
            loader: 'ts-loader',
            options: {
              transpileOnly: isDev, // Faster dev builds (skip type checking)
            },
          },
          exclude: /node_modules/,
        },
      ],
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
      alias: {
        '@': path.resolve(__dirname, 'extension'),
      },
    },
    plugins: [
      new CopyPlugin({
        patterns: [
          // Manifest goes to dist root
          { from: 'extension/manifest.json', to: 'manifest.json' },
          // Popup HTML and CSS (JS is bundled by webpack)
          { from: 'extension/popup/popup.html', to: 'popup/popup.html' },
          { from: 'extension/popup/popup.css',  to: 'popup/popup.css'  },
          // Icons
          {
            from: 'extension/icons',
            to:   'icons',
            noErrorOnMissing: true,
          },
        ],
      }),
    ],
    devtool: isDev ? 'inline-source-map' : false,
    optimization: {
      minimize: !isDev,
    },
    // Don't bundle node built-ins
    resolve: {
      extensions: ['.tsx', '.ts', '.js'],
      fallback: {
        path:   false,
        fs:     false,
        crypto: false,
      },
    },
  };
};
