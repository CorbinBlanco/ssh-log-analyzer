# SSH Security Log Analyzer

A Python tool that analyzes OpenSSH password authentication logs to flag repeated failed login attempts and potentially suspicious successful logins.

I built this project to practice working with regular expressions, dictionaries, sets, timestamps, and security logs.

## Future Development

I plan to expand this SSH log analyzer into a component of a larger Security Information and Event Management (SIEM) project. Future work will focus on collecting logs from multiple sources, standardizing event data, correlating activity across systems, and displaying alerts in a central dashboard.

The current version analyzes individual SSH log files and serves as an initial detection component for that broader project.

## Features

* Extracts usernames, source IP addresses, source ports, and timestamps.
* Groups failed and successful password logins by source IP.
* Flags IP addresses with at least five failed password attempts.
* Checks for successful logins from flagged IP addresses.
* Offers full and short reporting modes.
* Uses a file picker to select the log file.

## How Detection Works

The analyzer searches for `Failed password` and `Accepted password` entries.

An IP qualifies for further review when it has **at least five failed password attempts across the selected file**. A possible-compromise alert appears if its latest successful password login occurred **at or after its third failed attempt**.

These are separate conditions: five total failures qualify the IP, while the third failure is the timestamp used for comparison. An alert indicates activity worth investigating, not proof of account compromise.

## Report Modes

| Input | Mode                   | Output                                                                      |
| ----- | ---------------------- | --------------------------------------------------------------------------- |
| `1`   | Full security overview | Details for IPs with five or more failures, plus possible-compromise alerts |
| `2`   | Short summary          | Only possible-compromise alerts and their supporting details                |

Reports can include failure counts, failed and successful usernames, source ports, and login timestamps. The ports shown are client source ports, not necessarily the SSH server’s listening port.

## Requirements

* Python 3
* Tkinter
* A desktop environment for the file picker

The script uses `re`, `datetime`, and `tkinter`. No third-party Python packages are required.

## How to Run on Windows

1. Download `ssh_log_analyzer.py` and the log file you want to analyze.

2. Make sure Python with Tkinter is installed.

3. Find `ssh_log_analyzer.py` in File Explorer.

4. Right-click the script and select **Copy as path**.

5. Open **PowerShell**.

6. Type `py`, followed by a space, then paste the script’s full path. Keep the quotation marks.

   For example, replacing the path below with your actual file location:

   ```powershell
   py "C:\Users\blanc\PycharmProjects\SIEM Project\ssh_log_analyzer.py"
   ```

7. Press **Enter** to run the script.

8. Enter `1` for the full security overview or `2` for the short summary, then press **Enter**.

9. Select your log file in the file picker.

10. View the results in PowerShell.

You can also run the script from your selected IDE. In my case it's PyCharm

## Test Data

I tested this project using [OpenSSH_2k.log from LogPai’s Loghub repository](https://github.com/logpai/loghub/blob/master/OpenSSH/OpenSSH_2k.log).

To reproduce the example runs, download the raw log file and select it when prompted. The dataset is third-party test data; the analyzer is my project.

## Example Output

Both examples use the same `OpenSSH_2k.log` file:

* [Option 1 — Full security overview](examples/full_output.txt)
* [Option 2 — Short summary](examples/short_output.txt)

## Limitations

* Supports the password authentication patterns defined in the script; it does not analyze every type of SSH event, such as public-key authentication.
* Expects timestamps in the first 15 characters of each line, in a format such as `Dec 10 09:32:14`.
* Assigns **2026** when parsing timestamps. This is a code assumption, not a verified year for the test dataset. Logs spanning multiple years are not handled correctly.
* Counts failures across the entire file without a defined time window.
* Correlates events by IP address without requiring matching usernames. Shared IP addresses and legitimate login mistakes can produce false positives.
* Analyzes an existing file rather than monitoring logs in real time.
* Does not currently print an explicit “no matching alerts” message when no events meet the reporting conditions.

## What I Learned

* Using regular expressions and named capture groups to extract log fields.
* Organizing authentication records with dictionaries, sets, and lists.
* Sorting and comparing timestamps with Python’s `datetime` module.
* Building a file-selection interface with Tkinter.
* Understanding why simple detection rules need context before activity can be classified as malicious.

## Planned Improvements

* Add configurable failure thresholds and detection time windows.
* Improve timestamp handling and year selection.
* Add clearer messages when no matching activity is found.
* Reduce repeated code between report modes.
* Add automated tests using controlled sample logs.
