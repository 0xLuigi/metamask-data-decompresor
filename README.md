![MetaMask Decompressor Screenshot](https://github.com/0xLuigi/metamask-data-decompresor/blob/main/images/screenshot.png)

You can find instructions on how to locate your MetaMask Firefox data here: <br>
https://community.metamask.io/t/metamask-blank-screen-on-firefox-but-no-seed/12971/32

## Installation

1.  **Download the Tool:**
    You can download the latest version of the tool directly as a ZIP file here:
    [Download MetaMask Data Decompressor (ZIP)](https://github.com/0xLuigi/metamask-data-decompresor/archive/refs/heads/main.zip)
    After downloading, extract the contents to a folder of your choice.

2.  **Prepare Your MetaMask Data File:**
     Open the folder where you extracted the tool. Then, copy your MetaMask vault data file (the numbered file you located using the instructions above) into this same   folder.

3.  **Ensure Python is Installed:**
    This tool requires Python 3. If you don't have it installed, you can download it from the official Python website: [python.org](https://www.python.org/downloads/)

4.  **Run the Application:**
    Open your terminal or command prompt, navigate to the folder where you placed the tool and your MetaMask data file, and run the application:
    ```bash
    python mm_decomp.py
    ```
    This will launch the graphical user interface (GUI).

 ## Usage

Once the application is running:

* The tool should automatically detect your MetaMask vault file if it's located in the same directory as the `mm_decomp.py` script.
* Click the **"Decompress"** button.
* Within a few seconds, your file will be processed and saved as a text file named `[original_file_name]_decompressed.txt` in the same directory.
* If the program finds your MetaMask vault data, it will display it in the "MetaMask Vault Data" text area after the decompression and search are complete.
* You can also optionally enter an Ethereum (ETH) address in the "Search ETH Address" field. The program will search for this address within the decompressed content, helping you confirm if it's the correct file.

 ## 💖 Support the Project

If this tool helped you fix your MetaMask wallet, consider supporting the development:

- **Bitcoin (BTC):** `bc1qgug43r48cceja46j9nmj686wps5vad8appytsh`
- **Ethereum (ETH):** `0x8A00f43C099bEB3F5d3C289e8b93c71c32B4d52e`     
