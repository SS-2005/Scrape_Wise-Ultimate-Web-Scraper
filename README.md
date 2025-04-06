
# ScrapeWise - Ulitmate Web-Scraper Tool 🕵️‍♂️📊

**ScrapeWise** is a powerful web scraping and contact information extraction and verification tool designed to extract, validate, and analyze key contact details from any given website. It performs hybrid validation using APIs and custom logic, calculates confidence scores (How likely someone will respond if contacted), flags potential scam indicators, and generates a comprehensive CSV report.

---

## 🔧 Features

- 🌐 Scrape contact information from websites (emails, phone numbers, social media links).
- ✅ Validate extracted data using APIs and local logic.
- 📈 Generate confidence scores for each piece of contact information.
- 🚨 Detect and flag scam-like indicators (spammy domain names, suspicious language, etc.).
- 📁 Export results to a clean, readable CSV file.
- 🧠 Modular code structure for easy customization and scaling.

---

## 🛠️ Technologies Used

- **Python**
- **Requests**, **BeautifulSoup**, **re**, **validators**
- **Fake User-Agent Rotation**
- **3rd Party APIs** for email/phone validation (e.g., Numverify, Abstract API, Hunter.io)
- **CSV** and **JSON** handling

---

## 📦 Installation
Clone the repository or download ZIP file.
- `Note` : The version of the code is fully compatible with VS Code. It may not be fully Functionning with `Google Colab`.

## 🔑 API Keys Setup

This project uses external APIs for deep validation of contact info. You’ll need to register and obtain API keys from the following services:

### 1. Numverify (for phone validation)
- Website: https://numverify.com/
- Sign up and get your API key
- Free plan available

### 2. Abstract API (for email verification)
- Website: https://www.abstractapi.com/email-verification-validation-api
- Sign up and get your API key
- Free plan available

### 3. Hunter.io (for domain/email validation)
- Website: https://hunter.io/
- Create an account and get API key from dashboard
- Free plan available

Once you have the keys, update the respective code parts with `your_api_key`.

## 🚀 Usage

After project setup,Follow the steps to run the Web-Scraper.
1. Connect Your device with proper internet connection as the scraper required internet connection for fully functioning or as a result it may not generate desired output.
2. Run web_scrper.py
3. Input any link that you want to scrape from.
4. In the directory a csv file will be generated with the detailed information leads.

---

## 📊 Output

- The output CSV will include:
  - Contact Info (email, phone, social links)
  - Source URL
  - Confidence Score
  - Scam Indicator Flags
  - Validation Status

---

## Understanding The Output Columns:
Output Columns areas follows
1. type	:Contact type such as email,phone,twitter,instagram,etc
2. value :The contact information or link to the contact.
3. valid :Is the value a valid standard type or not (In Yes or No)
4. confidence :Contact Response likelihood score, How likely is the contact going to respond when reached.


## 📄 License

This project is licensed under the MIT License.

---

## 🙌 Contributions

PRs are welcome! Feel free to open issues or contribute enhancements.

---

## 👨‍💻 Author

Developed by Sahil Shaikh

---
