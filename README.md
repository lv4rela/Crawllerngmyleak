# Crawllerngmyleak

Crawllerngmyleak is a tool designed to identify sensitive information on web pages and JavaScript files. It uses Selenium to navigate and capture information from pages and scripts, searching for patterns such as API keys and authentication tokens.

## Features

- **Sensitive Information Detection**: Identifies common patterns of API keys, authentication tokens, and other sensitive data.
- **JS File Support**: Extracts and analyzes JavaScript files found on the page.
- **Headless Mode**: Runs the browser in headless mode for greater efficiency.

## Dependencies

Make sure you have the following dependencies installed:

- `selenium`
- `colorama`

Install the dependencies using `pip`:

```bash
pip install selenium colorama
