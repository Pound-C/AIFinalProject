from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time
import pandas as pd

# ------------------- Configuration -------------------
EMAIL = "your_email"
PASSWORD = "your_password"
KEYWORD = "Data Scientist"
LOCATION = "Thailand"
SCROLL_TIMES = 20  # Number of scrolls to load more jobs

# ------------------- Setup Driver --------------------
options = Options()
options.add_argument("--start-maximized")
driver = webdriver.Chrome(options=options)

# ------------------- Login ---------------------------
driver.get("https://www.linkedin.com/login")
time.sleep(2)

driver.find_element(By.ID, "username").send_keys(EMAIL)
driver.find_element(By.ID, "password").send_keys(PASSWORD)
driver.find_element(By.ID, "password").send_keys(Keys.RETURN)
time.sleep(3)

# ------------------- Job Search ----------------------
search_url = (
    f"https://www.linkedin.com/jobs/search/?keywords={KEYWORD}&location={LOCATION}"
)
driver.get(search_url)
time.sleep(3)

# Scroll to load more jobs
for _ in range(SCROLL_TIMES):
    driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
    time.sleep(2)

# ------------------- Scrape Job Info -----------------
job_cards = driver.find_elements(By.CLASS_NAME, "base-card")
job_data = []

for card in job_cards:
    try:
        card.click()
        time.sleep(2)

        job_title = driver.find_element(By.CLASS_NAME, "topcard__title").text
        company = driver.find_element(By.CLASS_NAME, "topcard__org-name-link").text
        location = driver.find_element(By.CLASS_NAME, "topcard__flavor--bullet").text
        posted_time = driver.find_element(By.CLASS_NAME, "posted-time-ago__text").text
        job_desc = driver.find_element(By.CLASS_NAME, "description__text").text[
            :500
        ]  # limit length

        # Optional: check for extra fields
        details = driver.find_elements(By.CLASS_NAME, "description__job-criteria-item")
        job_type = details[0].text if len(details) > 0 else "N/A"
        seniority = details[1].text if len(details) > 1 else "N/A"

        job_data.append(
            {
                "Title": job_title,
                "Company": company,
                "Location": location,
                "Posted": posted_time,
                "Job Type": job_type,
                "Seniority": seniority,
                "Description": job_desc,
            }
        )

    except Exception as e:
        print("Skipped a job due to error:", e)
        continue

# ------------------- Save Results --------------------
df = pd.DataFrame(job_data)
df.to_csv("linkedin_jobs.csv", index=False)
print("Saved to linkedin_jobs.csv")

driver.quit()
