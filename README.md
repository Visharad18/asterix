# asterix
Asterix RADAR Packet Analyzer and aircraft trajectory predictor

THis project expects a Packet Capture file (.pcap) as input containing packets received by RADAR systems from aircrafts with messages in ASTERIX format(specified by EuroControl). This project specifically takes into consideration CAT048 (Category-48) type messages, decodes various fields, converts all the values into a spreadsheets, aggregates various data-points on the basis of Aircraft codes and hence predict the further coordinates of aircrafts using machine machine learning and plot them.

This project was developed by me at Bharat Electronics Limited(BEL) during an internship. Though the script was developed by me, data for testing was provided by BEL, which is not included here to avoid any infringement, so you're required to arrange it for yourself. If any unintentional infringement is caused, please create an issue.

**Documentation of CAT048**
https://www.eurocontrol.int/publication/cat048-eurocontrol-specification-surveillance-data-exchange-asterix-part-4-category-48


Special thanks to Mr.Vaibhav Saini, Mr.Sachin Vashishth and Mr.Mukul Nautiyal of BEl for their guidance.
