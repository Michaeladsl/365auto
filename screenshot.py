#!/usr/bin/env python3
import os
import argparse
from io import BytesIO
from PIL import Image
from selenium import webdriver
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.edge.options import Options as EdgeOptions
from webdriver_manager.microsoft import EdgeChromiumDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def sanitize_filename(text):
    return text.replace(':', '_').replace(' ', '_').replace('.', '_').replace('/', '_')

def capture_screenshot(url, output_dir):
    # if they passed a Windows path, convert to file:// URL
    if not url.lower().startswith(("http://", "https://", "file://")):
        path = url.replace("\\", "/")
        url = f"file:///{path}"

    os.makedirs(output_dir, exist_ok=True)

    options = EdgeOptions()
    options.use_chromium = True
    options.add_argument("--headless")

    service = EdgeService(EdgeChromiumDriverManager().install())
    driver  = webdriver.Edge(service=service, options=options)
    driver.get(url)

    try:
        details = WebDriverWait(driver, 10).until(
            EC.presence_of_all_elements_located((By.CSS_SELECTOR, "details"))
        )

        for idx, detail in enumerate(details, start=1):
            summary = detail.find_element(By.TAG_NAME, "summary")
            if 'fail' in summary.get_attribute("class"):
                WebDriverWait(driver, 10).until(EC.element_to_be_clickable(summary))
                summary.click()

                pre = WebDriverWait(driver, 10).until(
                    EC.visibility_of(detail.find_element(By.TAG_NAME, "pre"))
                )

                name = sanitize_filename(summary.text)
                path = os.path.join(output_dir, f"{name}_screenshot_{idx}.png")

                png_data = pre.screenshot_as_png
                img      = Image.open(BytesIO(png_data))
                cropped  = img.crop((0, 1, img.width - 20, img.height))
                cropped.save(path)
                print(f"Saved: {path}")

    except Exception as e:
        print(f"An error occurred: {e}")

    finally:
        driver.quit()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Capture 'fail' screenshots from an HTML report via headless Edge"
    )
    parser.add_argument(
        "--url", required=True,
        help="URL or local file path to your HTML report"
    )
    parser.add_argument(
        "--output_dir", default="screenshots",
        help="Directory where screenshots will be saved"
    )
    args = parser.parse_args()

    capture_screenshot(args.url, args.output_dir)
