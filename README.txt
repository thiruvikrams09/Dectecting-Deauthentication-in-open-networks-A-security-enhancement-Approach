:DETECTING DEAUTHENTICATION ATTACKS IN OPEN NETWORKS: A SECURITY ENHANCED APPROACH"

This project focuses on detecting deauthentication attacks in open Wi-Fi networks using an ESP32-based embedded system. Wireless networks are highly vulnerable to attacks where malicious users send fake deauthentication packets to disconnect legitimate users.The proposed system continuously monitors wireless traffic by operating in promiscuous mode and identifies abnormal patterns based on packet count and rate thresholds. It also includes spoof detection by comparing attacker MAC addresses with known router addresses.The system provides real-time alerts using an OLED display, buzzer notifications, and automated email alerts. This approach offers a low-cost, portable, and efficient solution for improving wireless network security in environments such as colleges and public networks.

HARDWARE REQUIREMENTS:

ESP32 Development Board
OLED Display (0.96 inch, I2C)
Buzzer
Jumper Wires
Power Supply (USB / Battery)

SOFTWARE REQUIREMENTS:

Operating System : Windows / Linux
Technology : Embedded C (Arduino IDE)
Libraries Used :
WiFi.h
esp_wifi.h
Wire.h
Adafruit_GFX
Adafruit_SSD1306
ESP_Mail_Client
Preferences

INSTALLATION REQUIREMENTS:

Install required libraries in Arduino IDE:

WiFi  
esp_wifi  
Wire  
Adafruit SSD1306  
Adafruit GFX  
ESP Mail Client  
Preferences 
 
Steps:

Install Arduino IDE

Install ESP32 board package

Add required libraries using Library Manager

Upload the code to ESP32

Connect OLED display and buzzer properly

RUNNING THE PROJECT:

#DEMO

Steps:

Power ON the ESP32 device
System connects to configured Wi-Fi network
Device scans nearby routers
Promiscuous mode is enabled to capture packets
Deauthentication packets are detected
RSSI filtering removes weak signals
System identifies attackers and spoof attempts
OLED display shows real-time monitoring data
Buzzer alerts when attack is detected
10. Email notification is sent with attack details

##RESULT

The system successfully detects deauthentication attacks in real time and identifies malicious devices based on MAC addresses. It minimizes false alarms using signal strength filtering and provides instant alerts through display, sound, and email notifications. The proposed solution enhances wireless network security and can be effectively deployed in open environments such as campuses and public Wi-Fi zones.