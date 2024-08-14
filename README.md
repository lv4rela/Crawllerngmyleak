# Crawllerngmyleak

Crawllerngmyleak is a tool designed to identify sensitive information on web pages and JavaScript files. It uses Selenium to navigate and capture information from pages and scripts, searching for patterns such as API keys and authentication tokens.

## Features

- **Sensitive Information Detection**: Identifies common patterns of API keys, authentication tokens, and other sensitive data.
- **JS File Support**: Extracts and analyzes JavaScript files found on the page.
- **Headless Mode**: Runs the browser in headless mode for greater efficiency.

## Prerequisites

- Python 3.x
- **GeckoDriver:** Required for Selenium with Firefox. [Download GeckoDriver](https://github.com/mozilla/geckodriver/releases)

  
## Dependencies

Make sure you have the following dependencies installed:

- `selenium`
- `colorama`


## Installation

1. Clone the repository:

    ```bash
     git clone https://github.com/lv4rela/Crawllerngmyleak.git
     cd Crawllerngmyleak
    ```

2. Install the required Python packages:

    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Before running the script, ensure you have changed the GeckoDriver path to your own.

```python
def initialize_driver():
    options = Options()
    options.add_argument("--headless") 
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    service = Service("/path/to/geckodriver") <---------
    return webdriver.Firefox(service=service, options=options)
```


You can run the script with either a single URL or a file containing a list of URLs.

### Command-Line Arguments

- **`-u` or `--url`**: The URL of the web page to crawl.
- **`-f` or `--file`**: A file containing a list of URLs to crawl (one URL per line).

### Example Commands

**Crawling a single URL:**

```bash
python crawllerngmyleak.py -u https://www.example.com
```

**Crawling URLs from a file:**

```bash
python Crawllerngmyleak.py -f urls.txt
```
