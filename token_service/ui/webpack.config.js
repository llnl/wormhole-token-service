const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const publicPath = process.env.PUBLIC_PATH || 'static/';

module.exports = {
  entry: './src/index.js',
  mode: 'none',
  output: {
    filename: 'main.[contenthash].js',
    path: path.resolve(__dirname, '../static'),
    publicPath,
    clean: true,
  },
  module: {
    rules: [
      {
        test: /\.css$/,
        use: ['style-loader', 'css-loader', 'postcss-loader']
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, 'public/index.html'),
    })
  ],
};
