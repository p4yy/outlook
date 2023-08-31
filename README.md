# Outlook: A Guide

Credit: [https://github.com/beropex/Outlook-Hotmail-generator](https://github.com/beropex/Outlook-Hotmail-generator)

## Usage Instructions

Follow these steps to ensure a smooth experience while using the Outlook Generator.

1. **Install the Required Dependencies:**
   
   Begin by installing the necessary dependencies. Open your terminal and enter the following command:
   
   ```shell
   pip install -r requirements.txt
   ```

2. **Configure Your CAPSOLVER API Key:**

   In order to proceed, you need to set up your CAPSOLVER API key. Open the `config.json` file and replace 'YOUR_API_KEY' with your actual CAPSOLVER API key.

3. **Set Up Proxy List:**

   Prepare a list of proxies that you intend to use. Place all the proxy addresses in the `proxies.txt` file. Remember, using proxies is mandatory for this process.

4. **For Linux VPS Users:**

   If you are running this on a Linux VPS (Virtual Private Server), you must also install Node.js. You can typically do this using your system's package manager.

5. **Run the Application:**

   You're all set to generate Outlook accounts. Execute the following command in your terminal:
   
   ```shell
   python main.py
   ```
   
   Let the magic happen!
