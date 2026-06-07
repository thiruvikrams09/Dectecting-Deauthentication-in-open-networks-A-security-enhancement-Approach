#include <WiFi.h>
#include <esp_wifi.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <ESP_Mail_Client.h>
#include <Preferences.h>

// ================= HARDWARE =================
#define BUZZER_PIN 0

// ================= OLED =================
#define SCREEN_WIDTH 000
#define SCREEN_HEIGHT 00
#define OLED_RESET    -1
#define OLED_ADDRESS  0x3C
#define SDA_PIN 00
#define SCL_PIN 00

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

// ================= WIFI =================
#define WIFI_SSID "ssid"
#define WIFI_PASS "pass"

// ================= EMAIL =================
#define SMTP_HOST "smtp.gmail.com"
#define SMTP_PORT 465
#define SENDER_EMAIL "email"
#define APP_PASSWORD "pass"
#define RECIPIENT_EMAIL "email"
#define DEVICE_NAME "Kabilan-Hunter"

SMTPSession smtp;

// ================= PREFERENCES =================
Preferences prefs;

// ================= SETTINGS =================
#define MAX_ATTACKERS 20
#define MAX_ROUTERS 10
#define MAX_HISTORY 100
#define SCAN_INTERVAL 120000

// ================= DETECTION THRESHOLDS =================
int ALERT_THRESHOLD = 30;
const unsigned long WINDOW = 10000;
const unsigned long EMAIL_COOLDOWN = 300000;
const int RATE_THRESHOLD = 20;
const int MIN_RSSI = -85;

// ================= SILENT MODE TOGGLE =================
bool silentMode = true;

// ================= CHANNEL HOPPING =================
const int CHANNELS[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
const int NUM_CHANNELS = 13;
int currentChannel = 0;
unsigned long lastChannelHop = 0;
const unsigned long CHANNEL_HOP_TIME = 250;

// ================= ISR DATA =================
volatile int deauthCount = 0;
volatile bool newEvent = false;
volatile int lastRSSI_ISR = 0;
volatile uint8_t lastAttacker_ISR[6];
volatile uint8_t lastVictim_ISR[6];
volatile uint8_t lastBSSID_ISR[6];

// ================= ROUTER DATABASE =================
struct RouterEntry {
  uint8_t mac[6];
  char ssid[33];
  int channel;
  int rssi;
};

RouterEntry routers[MAX_ROUTERS];
int routerCount = 0;
String networkSSID = "";

// ================= VENDOR DATABASE =================
struct VendorEntry {
  uint8_t oui[3];
  const char* name;
};

const VendorEntry vendorDB[] = {
  {{0x00, 0x11, 0x22}, "Intel"}, {{0x00, 0x14, 0x22}, "Dell"},
  {{0x00, 0x1A, 0x11}, "Cisco"}, {{0x00, 0x1B, 0x77}, "Netgear"},
  {{0x00, 0x1C, 0x10}, "TP-Link"}, {{0x00, 0x1D, 0x60}, "Apple"},
  {{0x00, 0x1E, 0x52}, "Samsung"}, {{0x00, 0x1F, 0x33}, "Huawei"},
  {{0x00, 0x21, 0x6B}, "ASUS"}, {{0x00, 0x23, 0xCD}, "Xiaomi"},
  {{0x00, 0x24, 0x54}, "D-Link"}, {{0x00, 0x25, 0x9C}, "Belkin"},
  {{0x5A, 0x4D, 0xD3}, "Motorola"}, {{0x30, 0xCB, 0xC7}, "Realtek"},
  {{0x08, 0xF9, 0x7E}, "Broadcom"}, {{0x6A, 0xC6, 0xAC}, "ESP Device"},
  {{0xCC, 0xCC, 0xCC}, "Random/Mobile"}, {{0xAA, 0xAA, 0xAA}, "Random/Desktop"},
  {{0x00, 0x50, 0xF1}, "Microsoft"}, {{0x00, 0x1E, 0x58}, "Sony"},
  {{0x00, 0x26, 0x5B}, "LG"}, {{0x00, 0x23, 0x76}, "Panasonic"},
  {{0x00, 0x24, 0xE4}, "Toshiba"}, {{0x00, 0x1A, 0xA0}, "Acer"},
  {{0x00, 0x1E, 0x8C}, "Hewlett Packard"}
};

// ================= ATTACKER DATABASE =================
struct Attacker {
  uint8_t mac[6];
  char macStr[18];
  char vendor[12];
  unsigned long firstSeen;
  unsigned long lastSeen;
  uint16_t deauthCount;
  uint8_t peakRate;
  uint8_t currentRate;
  int8_t rssiAvg;
  bool alerted : 1;
  bool isSpoofing : 1;
  bool active : 1;
  unsigned long lastRateCalc;
  uint8_t targetNetwork[6];
  int targetChannel;
  
  // ===== NEW FEATURES =====
  unsigned long attackDuration;
  int intensityScore;
};

Attacker attackers[MAX_ATTACKERS];
int attackerCount = 0;

// ================= DEAUTH HISTORY =================
struct DeauthEvent {
  unsigned long timestamp;
  uint8_t attacker[6];
  uint8_t target[6];
  int rssi;
  int channel;
};

DeauthEvent deauthHistory[MAX_HISTORY];
int historyIndex = 0;

// ================= STATS =================
unsigned long totalDeauths = 0;
int confirmedAttacks = 0;
unsigned long lastEmailTime = 0;
int emailSuccessCount = 0;
bool attackOngoing = false;
unsigned long lastTotalDeauths = 0;

// ================= OLED =================
int oledPage = 0;
unsigned long lastPageChange = 0;
const unsigned long PAGE_DURATION = 3000;

// ================= ATTACK PATTERN ENUM =================
enum AttackPattern { PATTERN_NORMAL, PATTERN_BURST, PATTERN_STEALTH, PATTERN_SPOOF };

// ================= UTILS =================
void macToChar(const uint8_t *mac, char *output){
  if(mac == NULL) { 
    strcpy(output, "00:00:00:00:00:00"); 
    return; 
  }
  sprintf(output, "%02X:%02X:%02X:%02X:%02X:%02X", 
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

String macToStr(const uint8_t *mac){ char s[18]; macToChar(mac, s); return String(s); }

void getVendorStr(const uint8_t *mac, char *output){
  for(int i=0; i<sizeof(vendorDB)/sizeof(VendorEntry); i++) {
    if(mac[0] == vendorDB[i].oui[0] && mac[1] == vendorDB[i].oui[1] && mac[2] == vendorDB[i].oui[2]) {
      strcpy(output, vendorDB[i].name); return;
    }
  }
  strcpy(output, "Unknown");
}

bool isBroadcast(const uint8_t *mac){ for(int i=0;i<6;i++) if(mac[i]!=0xFF) return false; return true; }
bool macsEqual(const uint8_t *a, const uint8_t *b){ for(int i=0;i<6;i++) if(a[i]!=b[i]) return false; return true; }

// ================= INTENSITY SCORE FUNCTION =================
int calculateIntensityScore(int deauthCount, int rate, int rssi) {
  int score = 0;
  
  // Deauth count contribution (max 40)
  if(deauthCount > 100) score += 40;
  else if(deauthCount > 75) score += 35;
  else if(deauthCount > 50) score += 30;
  else if(deauthCount > 30) score += 20;
  else if(deauthCount > 15) score += 10;
  else if(deauthCount > 5) score += 5;
  
  // Rate contribution (max 40)
  if(rate > 50) score += 40;
  else if(rate > 40) score += 35;
  else if(rate > 30) score += 30;
  else if(rate > 20) score += 20;
  else if(rate > 10) score += 10;
  else if(rate > 5) score += 5;
  
  // RSSI contribution (max 20) - closer = more dangerous
  if(rssi > -50) score += 20;
  else if(rssi > -60) score += 15;
  else if(rssi > -70) score += 10;
  else if(rssi > -80) score += 5;
  
  return score;
}

// ================= SORT ATTACKERS BY INTENSITY =================
void sortAttackersByIntensity() {
  for(int i=0; i<attackerCount-1; i++) {
    for(int j=i+1; j<attackerCount; j++) {
      if(attackers[j].deauthCount > attackers[i].deauthCount) {
        Attacker temp = attackers[i];
        attackers[i] = attackers[j];
        attackers[j] = temp;
      }
    }
  }
}

// ================= ROUTER DATABASE FUNCTIONS =================
bool isRouterMAC(const uint8_t *mac){
  for(int i=0; i<routerCount; i++) if(macsEqual(routers[i].mac, mac)) return true;
  return false;
}

String getRouterName(const uint8_t *mac) {
  for(int i=0; i<routerCount; i++) if(macsEqual(routers[i].mac, mac)) return String(routers[i].ssid);
  return "Unknown Network";
}

void addRouterMAC(const uint8_t *mac, const char* ssid, int channel, int rssi){
  if(routerCount >= MAX_ROUTERS) return;
  for(int i=0; i<routerCount; i++) if(macsEqual(routers[i].mac, mac)) return;
  memcpy(routers[routerCount].mac, mac, 6);
  strncpy(routers[routerCount].ssid, ssid, 32);
  routers[routerCount].ssid[32] = '\0';
  routers[routerCount].channel = channel;
  routers[routerCount].rssi = rssi;
  routerCount++;
}

// ================= SCAN FOR ROUTERS =================
void scanForRouters() {
  WiFi.mode(WIFI_STA);
  int n = WiFi.scanNetworks();
  if(n > 0) {
    networkSSID = WiFi.SSID(0);
    for(int i=0; i<n && routerCount < MAX_ROUTERS; i++) {
      uint8_t routerBSSID[6] = {0};
      if(WiFi.BSSID(i, routerBSSID)) {
        addRouterMAC(routerBSSID, WiFi.SSID(i).c_str(), WiFi.channel(i), WiFi.RSSI(i));
      }
    }
  }
  WiFi.scanDelete();
}

// ================= SHOW NEARBY NETWORKS =================
void showNearbyNetworks() {
  Serial.println("\n📡 SCANNING FOR NEARBY NETWORKS...");
  Serial.println("=================================");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  int n = WiFi.scanNetworks();
  if(n == 0) { Serial.println("❌ No networks found!"); }
  else {
    Serial.print("✅ Found "); Serial.print(n); Serial.println(" networks");
    Serial.println("---------------------------------");
    int indices[n];
    for(int i=0; i<n; i++) indices[i] = i;
    for(int i=0; i<n-1; i++) {
      for(int j=i+1; j<n; j++) {
        if(WiFi.RSSI(indices[j]) > WiFi.RSSI(indices[i])) {
          int temp = indices[i]; indices[i] = indices[j]; indices[j] = temp;
        }
      }
    }
    for(int i=0; i<n; i++) {
      int idx = indices[i];
      Serial.print(i+1); Serial.print(". ");
      int rssi = WiFi.RSSI(idx);
      if(rssi > -50) Serial.print("🟢 "); else if(rssi > -65) Serial.print("🟡 ");
      else if(rssi > -75) Serial.print("🟠 "); else Serial.print("🔴 ");
      String ssid = WiFi.SSID(idx);
      if(ssid.length() == 0) Serial.print("[HIDDEN NETWORK]"); else Serial.print(ssid);
      uint8_t bssid[6]; WiFi.BSSID(idx, bssid);
      char bssidStr[18]; macToChar(bssid, bssidStr);
      Serial.print(" ("); Serial.print(bssidStr); Serial.print(")");
      Serial.print(" | CH:"); Serial.print(WiFi.channel(idx));
      Serial.print(" | "); Serial.print(rssi); Serial.print(" dBm");
      if(ssid == WIFI_SSID) Serial.print(" ⭐ CONNECTED");
      Serial.println();
    }
    Serial.println("---------------------------------");
    Serial.print("📊 Strongest: ");
    if(n > 0) {
      String strongestSSID = WiFi.SSID(indices[0]);
      if(strongestSSID.length() == 0) Serial.print("Hidden Network"); else Serial.print(strongestSSID);
      Serial.print(" ("); Serial.print(WiFi.RSSI(indices[0])); Serial.println(" dBm)");
    }
  }
  WiFi.scanDelete();
  Serial.println("=================================\n");
}

// ================= Bounds Checking & MAC Validation =================
bool isValidMAC(const uint8_t *mac) { for(int i=0; i<6; i++) if(mac[i] != 0) return true; return false; }

// ================= False-Positive Filtering =================
bool isFalsePositive(const uint8_t *mac, int rssi, int rate, int attackerId) {
  uint8_t myMac[6]; WiFi.macAddress(myMac);
  if(macsEqual(mac, myMac)) return true;
  if(isRouterMAC(mac)) {
    if(rate < 2 && attackerId >= 0 && attackers[attackerId].deauthCount < 5) return true;
  }
  if(rssi < MIN_RSSI - 10) return true;
  return false;
}

// ================= Attack Severity =================
String getAttackSeverity(int deauthCount, int rate, int rssi) {
  if(deauthCount > 100 || rate > 50) return "CRITICAL";
  if(deauthCount > 50 || rate > 30) return "HIGH";
  if(deauthCount > 25 || rate > 15) return "MEDIUM";
  return "LOW";
}

// ================= Smart Time Window Detection =================
unsigned long getDynamicWindow(int currentRate) {
  if(currentRate > 50) return 1000;
  if(currentRate > 20) return 3000;
  return 5000;
}

// ================= Attack Pattern Recognition =================
AttackPattern detectPattern(int attackerId) {
  Attacker* a = &attackers[attackerId];
  if(a->peakRate > 30 && a->deauthCount > 50) return PATTERN_BURST;
  if(a->peakRate < 10 && a->deauthCount > 100) return PATTERN_STEALTH;
  if(a->isSpoofing) return PATTERN_SPOOF;
  return PATTERN_NORMAL;
}

String getPatternString(AttackPattern pattern) {
  switch(pattern) {
    case PATTERN_BURST: return "BURST";
    case PATTERN_STEALTH: return "STEALTH";
    case PATTERN_SPOOF: return "SPOOF";
    default: return "NORMAL";
  }
}

// ================= Save/Load Stats =================
void saveStats() {
  prefs.begin("hunter", false);
  prefs.putULong("totalDeauths", totalDeauths);
  prefs.putInt("confirmedAttacks", confirmedAttacks);
  prefs.putInt("emailSuccess", emailSuccessCount);
  prefs.end();
}

void loadStats() {
  prefs.begin("hunter", true);
  totalDeauths = prefs.getULong("totalDeauths", 0);
  confirmedAttacks = prefs.getInt("confirmedAttacks", 0);
  emailSuccessCount = prefs.getInt("emailSuccess", 0);
  prefs.end();
}

// ================= TOGGLE SILENT MODE =================
void toggleSilentMode() {
  silentMode = !silentMode;
  Serial.println("\n🔊 SILENT MODE: " + String(silentMode ? "ON" : "OFF"));
  Serial.println(silentMode ? "✓ Only ATTACKS will show" : "✓ All messages will show");
}

// ================= RESET ALL STATS =================
void resetAllStats() {
  Serial.println("\n⚠️ RESETTING ALL STATS...");
  totalDeauths = 0; confirmedAttacks = 0; emailSuccessCount = 0;
  attackerCount = 0; routerCount = 0; lastEmailTime = 0;
  for(int i=0; i<MAX_ATTACKERS; i++) { 
    attackers[i].deauthCount = 0; 
    attackers[i].alerted = false;
    attackers[i].attackDuration = 0;
    attackers[i].intensityScore = 0;
  }
  prefs.begin("hunter", false);
  prefs.putULong("totalDeauths", 0); prefs.putInt("confirmedAttacks", 0);
  prefs.putInt("emailSuccess", 0); prefs.putInt("alertThreshold", ALERT_THRESHOLD);
  prefs.end();
  Serial.println("✅ ALL STATS RESET TO ZERO!");
}

// ================= Power Management =================
void powerManagement() {
  static unsigned long lastActive = millis();
  static unsigned long lastTotalDeauths = 0;
  if(millis() - lastActive > 300000) {
    if(totalDeauths == lastTotalDeauths) {
      static bool powerSaveMode = false;
      if(!powerSaveMode) powerSaveMode = true;
    }
  }
  if(newEvent) { lastActive = millis(); lastTotalDeauths = totalDeauths; }
}

// ================= ATTACKER FUNCTIONS =================
int findAttacker(const uint8_t *mac){
  for(int i=0; i<attackerCount; i++) if(macsEqual(attackers[i].mac, mac)) return i;
  return -1;
}

int findAttackerByTarget(const uint8_t *attacker, const uint8_t *target) {
  for(int i=0; i<attackerCount; i++) {
    if(macsEqual(attackers[i].mac, attacker) && macsEqual(attackers[i].targetNetwork, target)) return i;
  }
  return -1;
}

int addAttacker(const uint8_t *mac, const uint8_t *target, int channel){
  if(attackerCount >= MAX_ATTACKERS) {
    for(int i=1; i<MAX_ATTACKERS; i++) attackers[i-1] = attackers[i];
    attackerCount = MAX_ATTACKERS - 1;
  }
  int id = attackerCount;
  memcpy(attackers[id].mac, mac, 6);
  memcpy(attackers[id].targetNetwork, target, 6);
  attackers[id].targetChannel = channel;
  macToChar(mac, attackers[id].macStr);
  getVendorStr(mac, attackers[id].vendor);
  attackers[id].firstSeen = millis();
  attackers[id].lastSeen = millis();
  attackers[id].deauthCount = 1;
  attackers[id].peakRate = 1;
  attackers[id].currentRate = 1;
  attackers[id].rssiAvg = lastRSSI_ISR;
  attackers[id].alerted = false;
  attackers[id].isSpoofing = isRouterMAC(mac);
  attackers[id].active = true;
  attackers[id].lastRateCalc = millis();
  
  // ===== NEW FEATURES INIT =====
  attackers[id].attackDuration = 0;
  attackers[id].intensityScore = 0;
  
  attackerCount++;
  if(!silentMode) {
    if(attackers[id].isSpoofing) Serial.print("⚠️ New SPOOF attacker: ");
    else Serial.print("⚠️ New attacker: ");
    Serial.println(attackers[id].macStr);
  }
  return id;
}

// ================= RATE CALCULATION =================
int calculateRate(const uint8_t *attacker, const uint8_t *target){
  int count = 0;
  unsigned long now = millis();
  for(int i=0; i<MAX_HISTORY; i++) {
    if(macsEqual(deauthHistory[i].attacker, attacker) &&
       macsEqual(deauthHistory[i].target, target) &&
       now - deauthHistory[i].timestamp < WINDOW) count++;
  }
  return count;
}

// ================= ATTACKER UPDATE =================
void updateAttacker(const uint8_t *mac, const uint8_t *target, int rssi, int rate, int channel){
  int id = findAttackerByTarget(mac, target);
  if(id == -1) id = addAttacker(mac, target, channel);
  if(id >= 0){
    attackers[id].lastSeen = millis();
    attackers[id].deauthCount++;
    attackers[id].currentRate = rate;
    attackers[id].rssiAvg = (attackers[id].rssiAvg + rssi) / 2;
    attackers[id].targetChannel = channel;
    
    // ===== UPDATE NEW FEATURES =====
    attackers[id].attackDuration = (millis() - attackers[id].firstSeen) / 1000;
    attackers[id].intensityScore = calculateIntensityScore(
      attackers[id].deauthCount, 
      attackers[id].currentRate, 
      attackers[id].rssiAvg
    );
    
    if(rate > attackers[id].peakRate && rate < 255) attackers[id].peakRate = rate;
    if(isFalsePositive(mac, rssi, rate, id)) return;
    
    bool shouldAlert = false;
    if(rate >= RATE_THRESHOLD && attackers[id].deauthCount >= 15) shouldAlert = true;
    if(attackers[id].deauthCount >= ALERT_THRESHOLD) shouldAlert = true;
    if(attackers[id].isSpoofing && attackers[id].deauthCount >= 10) shouldAlert = true;
    
    if(shouldAlert && !attackers[id].alerted){
      attackers[id].alerted = true;
      confirmedAttacks++;
      saveStats();
      char reason[100];
      char targetStr[18]; macToChar(target, targetStr);
      if(attackers[id].isSpoofing) {
        sprintf(reason, "SPOOF ATTACK on %s: %d deauths at %d/s", targetStr, attackers[id].deauthCount, rate);
      } else if(rate >= RATE_THRESHOLD) {
        sprintf(reason, "HIGH RATE ATTACK on %s: %d deauths at %d/s", targetStr, attackers[id].deauthCount, rate);
      } else {
        sprintf(reason, "DEAUTH FLOOD on %s: %d deauths detected", targetStr, attackers[id].deauthCount);
      }
      triggerAlert(id, reason, target);
    }
  }
}

// ================= TRIGGER ALERT =================
void triggerAlert(int attackerId, char *reason, const uint8_t *target){
  Serial.println("\n⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️");
  Serial.println("🔴 KABILAN HUNTER - ATTACK DETECTED!");
  Serial.println("⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️⚠️");
  
  AttackPattern pattern = detectPattern(attackerId);
  String severity = getAttackSeverity(attackers[attackerId].deauthCount, 
                                      attackers[attackerId].currentRate,
                                      attackers[attackerId].rssiAvg);
  
  char targetStr[18]; macToChar(target, targetStr);
  String networkName = getRouterName(target);
  
  Serial.print("📡 Network Under Attack: ");
  if(networkName.length() > 0) Serial.print(networkName);
  else Serial.print("Hidden Network");
  Serial.print(" ("); Serial.print(targetStr); Serial.println(")");
  
  if(attackers[attackerId].isSpoofing) {
    Serial.println("⚠️ SPOOFING ATTACK!");
    Serial.println("⚠️ Attacker using router MAC!");
  }
  
  Serial.print("📊 Severity: "); Serial.println(severity);
  Serial.print("📊 Pattern: "); Serial.println(getPatternString(pattern));
  Serial.print("👤 Attacker MAC: "); Serial.println(attackers[attackerId].macStr);
  Serial.print("🏭 Vendor: "); Serial.println(attackers[attackerId].vendor);
  Serial.print("📊 Deauths: "); Serial.println(attackers[attackerId].deauthCount);
  Serial.print("⚡ Rate: "); Serial.print(attackers[attackerId].currentRate); Serial.println("/s");
  Serial.print("📶 RSSI: "); Serial.print(attackers[attackerId].rssiAvg); Serial.println(" dBm");
  Serial.print("📻 Channel: "); Serial.println(attackers[attackerId].targetChannel);
  
  // ===== SHOW DURATION AND INTENSITY =====
  unsigned long duration = attackers[attackerId].attackDuration;
  int mins = duration / 60; int secs = duration % 60;
  Serial.print("⏱️ Duration: ");
  if(mins > 0) { Serial.print(mins); Serial.print("m "); }
  Serial.print(secs); Serial.println("s");
  
  Serial.print("🔥 Intensity: "); Serial.print(attackers[attackerId].intensityScore); Serial.println("/100");
  
  Serial.print("⚠️ Reason: "); Serial.println(reason);
  Serial.println("===================================\n");
  
  for(int i=0; i<3; i++){ digitalWrite(BUZZER_PIN, HIGH); delay(200); digitalWrite(BUZZER_PIN, LOW); delay(200); }
  
  attackOngoing = true;
  sendEmail(attackerId, reason, severity, pattern, target);
}

// ================= SNIFFER =================
void IRAM_ATTR sniffer(void* buf, wifi_promiscuous_pkt_type_t pkt_type){
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
  if(pkt->rx_ctrl.sig_len < 24) return;
  uint8_t *frame = pkt->payload;
  int rssi = pkt->rx_ctrl.rssi;
  if(rssi < MIN_RSSI) return;
  uint8_t frameControl = frame[0];
  uint8_t frameType = (frameControl >> 2) & 0x03;
  uint8_t frameSubtype = (frameControl >> 4) & 0x0F;
  if(frameType == 0 && frameSubtype == 12){
    uint8_t *addr2 = frame+10;
    uint8_t *addr3 = frame+16;
    deauthCount++; totalDeauths++;
    lastRSSI_ISR = rssi;
    for(int i=0; i<6; i++) {
      lastAttacker_ISR[i] = addr2[i];
      lastBSSID_ISR[i] = addr3[i];
    }
    newEvent = true;
  }
}

// ================= PROCESS EVENT =================
void processEvent(){
  if(!newEvent) return;
  newEvent = false;
  if(historyIndex >= MAX_HISTORY) historyIndex = 0;
  uint8_t tempAttacker[6]; uint8_t tempTarget[6];
  int tempRSSI = lastRSSI_ISR;
  for(int i=0; i<6; i++) {
    tempAttacker[i] = lastAttacker_ISR[i];
    tempTarget[i] = lastBSSID_ISR[i];
  }
  uint8_t tempCheck[6]; 
  for(int i=0; i<6; i++) tempCheck[i] = lastAttacker_ISR[i];
  if(!isValidMAC(tempCheck)) return;
  for(int i=0; i<6; i++) {
    deauthHistory[historyIndex].attacker[i] = tempAttacker[i];
    deauthHistory[historyIndex].target[i] = tempTarget[i];
  }
  deauthHistory[historyIndex].timestamp = millis();
  deauthHistory[historyIndex].rssi = tempRSSI;
  deauthHistory[historyIndex].channel = currentChannel + 1;
  historyIndex = (historyIndex + 1) % MAX_HISTORY;
  int rate = calculateRate(tempAttacker, tempTarget);
  updateAttacker(tempAttacker, tempTarget, tempRSSI, rate, currentChannel + 1);
  
  if(!silentMode) {
    static unsigned long lastPrint = 0;
    if(millis() - lastPrint > 200) {
      lastPrint = millis();
      char attackerStr[18]; char targetStr[18];
      macToChar(tempAttacker, attackerStr); macToChar(tempTarget, targetStr);
      String networkName = getRouterName(tempTarget);
      Serial.print("📡 Deauth: "); Serial.print(attackerStr); Serial.print(" → ");
      if(networkName.length() > 0) Serial.print(networkName.substring(0, 15));
      else Serial.print(targetStr);
      Serial.print(" CH:"); Serial.print(currentChannel + 1);
      Serial.print(" RSSI:"); Serial.print(tempRSSI);
      Serial.print(" Rate:"); Serial.println(rate);
    }
  }
}

// ================= PERIODIC SCAN =================
void periodicScan() {
  static unsigned long lastScan = 0;
  if(millis() - lastScan > SCAN_INTERVAL) {
    lastScan = millis();
    esp_wifi_set_promiscuous(false); delay(100);
    scanForRouters(); delay(100);
    esp_wifi_set_promiscuous(true);
  }
}

// ================= OLED =================
bool initOLED() {
  Wire.begin(SDA_PIN, SCL_PIN);
  Wire.beginTransmission(OLED_ADDRESS);
  if(Wire.endTransmission() != 0) { Serial.println("❌ OLED not found!"); return false; }
  if(!display.begin(SSD1306_SWITCHCAPVCC, OLED_ADDRESS)) { Serial.println("❌ OLED begin failed!"); return false; }
  return true;
}

void updateDisplay() {
  display.clearDisplay();
  display.setTextSize(1); display.setTextColor(SSD1306_WHITE);
  display.setCursor(0,0); display.println("KABILAN HUNTER");
  display.drawLine(0, 8, 128, 8, SSD1306_WHITE);
  if(millis() - lastPageChange > PAGE_DURATION) { oledPage = (oledPage + 1) % 5; lastPageChange = millis(); }
  if(oledPage == 0) {
    display.setCursor(0,12); display.print("Networks: "); display.println(routerCount);
    display.setCursor(0,22); display.print("Attackers: "); display.println(attackerCount);
    display.setCursor(0,32); display.print("Deauths: "); display.println(totalDeauths);
  } else if(oledPage == 1) {
    display.setCursor(0,12); display.print("Alerts: "); display.println(confirmedAttacks);
    display.setCursor(0,22); display.print("Email: "); display.println(emailSuccessCount);
    display.setCursor(0,32); display.print("Channel: "); display.println(currentChannel+1);
  } else if(oledPage == 2) {
    display.setCursor(0,12); display.println("SPOOF DETECT");
    display.setCursor(0,22); display.print("Rate Thresh: "); display.println(RATE_THRESHOLD);
    display.setCursor(0,32); display.print("Window: "); display.print(WINDOW/1000); display.println("s");
  } else if(oledPage == 3) {
    display.setCursor(0,12); display.println(silentMode ? "SILENT MODE ON" : "VERBOSE MODE");
    display.setCursor(0,22); display.print("Networks: "); display.println(routerCount);
    display.setCursor(0,32); display.print("Active: "); display.println(attackerCount);
  } else if(oledPage == 4) {
    display.setCursor(0,12); display.println("TOP ATTACKER");
    if(attackerCount > 0) {
      sortAttackersByIntensity();
      display.setCursor(0,22); display.println(attackers[0].macStr);
      display.setCursor(0,32); display.print("Intensity: ");
      display.print(attackers[0].intensityScore);
      display.println("/100");
    } else {
      display.setCursor(0,22); display.println("No attackers");
    }
  }
  display.drawLine(0, 54, 128, 54, SSD1306_WHITE);
  display.setCursor(0,56); display.print("Page "); display.print(oledPage+1); display.println("/5");
  display.display();
}

// ================= SETUP WIFI =================
bool setupWiFi() {
  Serial.print("Connecting to "); Serial.print(WIFI_SSID); Serial.print(" ");
  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  int attempts = 0;
  while(WiFi.status() != WL_CONNECTED && attempts < 30) { delay(500); Serial.print("."); attempts++; }
  Serial.println();
  if(WiFi.status() == WL_CONNECTED) {
    Serial.println("✅✅✅ WiFi Connected Successfully! ✅✅✅");
    Serial.println("\n📡 CONNECTION DETAILS:"); Serial.println("=================================");
    Serial.print("SSID: "); Serial.println(WIFI_SSID);
    uint8_t bssid[6]; WiFi.BSSID(bssid); char bssidStr[18]; macToChar(bssid, bssidStr);
    Serial.print("BSSID: "); Serial.println(bssidStr);
    Serial.print("Channel: "); Serial.println(WiFi.channel());
    Serial.print("Signal: "); int rssi = WiFi.RSSI(); Serial.print(rssi); Serial.print(" dBm ");
    if(rssi > -50) Serial.println("(🟢 Excellent)");
    else if(rssi > -65) Serial.println("(🟡 Good)");
    else if(rssi > -75) Serial.println("(🟠 Fair)");
    else Serial.println("(🔴 Weak)");
    Serial.print("IP Address: "); Serial.println(WiFi.localIP());
    Serial.println("=================================\n");
    showNearbyNetworks();
    scanForRouters();
    return true;
  } else { Serial.println("❌ WiFi Connection Failed!"); return false; }
}

// ================= TEST EMAIL =================
void testEmail() {
  Serial.println("\n📧 TESTING EMAIL...");
  uint8_t testTarget[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  char testReason[] = "TEST EMAIL - System Working Properly";
  int oldAttackerCount = attackerCount;
  uint8_t testAttacker[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
  int id = addAttacker(testAttacker, testTarget, 6);
  if(id >= 0) {
    attackers[id].alerted = false;
    sendEmail(id, testReason, "TEST", PATTERN_NORMAL, testTarget);
    if(oldAttackerCount == attackerCount - 1) attackerCount = oldAttackerCount;
  } else Serial.println("❌ Failed to create test attacker");
}

// ===== UPDATED EMAIL WITH INTENSITY AND TOP ATTACKERS =====
void sendEmail(int attackerId, char *reason, String severity, AttackPattern pattern, const uint8_t *target){
  if(lastEmailTime > 0 && millis() - lastEmailTime < EMAIL_COOLDOWN){
    unsigned long waitTime = (EMAIL_COOLDOWN - (millis() - lastEmailTime)) / 1000;
    Serial.println("⏳ Cooldown - Wait " + String(waitTime) + "s"); return;
  }
  
  Serial.println("\n📧 SENDING ALERT...");
  int savedChannel = currentChannel;
  esp_wifi_set_promiscuous(false); delay(100);
  
  if(WiFi.status() != WL_CONNECTED) {
    Serial.println("📧 WiFi disconnected, reconnecting...");
    WiFi.reconnect();
    int attempts = 0;
    while(WiFi.status() != WL_CONNECTED && attempts < 20) { delay(500); Serial.print("."); attempts++; }
    Serial.println();
  }
  
  if(WiFi.status() == WL_CONNECTED){
    Session_Config config;
    config.server.host_name = SMTP_HOST; config.server.port = SMTP_PORT;
    config.login.email = SENDER_EMAIL; config.login.password = APP_PASSWORD;
    config.login.user_domain = F("127.0.0.1");
    
    SMTP_Message message;
    message.sender.name = DEVICE_NAME; message.sender.email = SENDER_EMAIL;
    message.subject = "🚨 KABILAN HUNTER - SECURITY ALERT";
    message.addRecipient("Admin", RECIPIENT_EMAIL);
    
    char targetStr[18]; macToChar(target, targetStr);
    String networkName = getRouterName(target);
    
    // ===== SORT ATTACKERS BY INTENSITY =====
    sortAttackersByIntensity();
    
    String body = "";
    body += "====================================\n";
    body += "   KABILAN HUNTER - SECURITY ALERT\n";
    body += "====================================\n\n";
    
    body += "🔴 ATTACK DETECTED!\n";
    body += "📊 Severity: "; body += severity; body += "\n";
    body += "📊 Attack Pattern: "; body += getPatternString(pattern); body += "\n";
    body += "📊 Reason: "; body += reason; body += "\n\n";
    
    // ===== CURRENT ATTACKER DETAILS =====
    body += "━━━━ CURRENT ATTACKER ━━━━━\n";
    body += "📱 MAC: "; body += attackers[attackerId].macStr; body += "\n";
    body += "🏭 Vendor: "; body += attackers[attackerId].vendor; body += "\n";
    body += "🎯 Target: "; body += networkName; body += " ("; body += targetStr; body += ")\n";
    body += "📊 Deauths: "; body += String(attackers[attackerId].deauthCount); body += "\n";
    body += "⚡ Rate: "; body += String(attackers[attackerId].currentRate); body += "/s\n";
    body += "📶 RSSI: "; body += String(attackers[attackerId].rssiAvg); body += " dBm\n";
    body += "📻 Channel: "; body += String(attackers[attackerId].targetChannel); body += "\n";
    
    // ===== INTENSITY SCORE WITH BAR =====
    int intensity = attackers[attackerId].intensityScore;
    body += "🔥 Intensity: "; body += String(intensity); body += "/100";
    body += " [";
    int bars = map(intensity, 0, 100, 0, 10);
    for(int b=0; b<10; b++) {
      if(b < bars) body += "█";
      else body += "░";
    }
    body += "]\n\n";
    
    // ===== ATTACK DURATION =====
    unsigned long duration = attackers[attackerId].attackDuration;
    int mins = duration / 60; int secs = duration % 60;
    body += "⏱️ Duration: ";
    if(mins > 0) { body += String(mins); body += "m "; }
    body += String(secs); body += "s\n\n";
    
    // IMMEDIATE ACTIONS
    body += "━━━━ IMMEDIATE ACTIONS ━━━━━\n";
    body += "1️⃣ LOCATE THE ATTACKER\n";
    body += "   • Walk around with your device\n";
    body += "   • Signal gets stronger when near\n";
    body += "   • Current RSSI: "; body += String(attackers[attackerId].rssiAvg); body += " dBm\n\n";
    
    body += "2️⃣ BLOCK THE ATTACKER\n";
    body += "   • Go to router admin page\n";
    body += "   • Add this MAC to blacklist: "; body += attackers[attackerId].macStr; body += "\n";
    body += "   • Enable MAC filtering\n";
    body += "   • Change WiFi password\n\n";
    
    body += "3️⃣ SECURE YOUR NETWORK\n";
    body += "   • Enable WPA3 if available\n";
    body += "   • Disable WPS\n";
    body += "   • Update router firmware\n";
    body += "   • Reduce transmit power\n\n";
    
    // NETWORK STATS
    body += "━━━━ NETWORK STATS ━━━━━━━━\n";
    body += "📡 Networks Found: "; body += String(routerCount); body += "\n";
    
    if(routerCount > 0) {
      body += "📋 Available Networks:\n";
      for(int i=0; i<routerCount; i++) {
        char macStr[18]; macToChar(routers[i].mac, macStr);
        body += "   • "; body += String(routers[i].ssid);
        body += " ("; body += macStr; body += ") CH:";
        body += String(routers[i].channel); body += " RSSI:";
        body += String(routers[i].rssi); body += "dBm\n";
      }
    }
    body += "\n";
    
    // ===== TOP ATTACKERS LEADERBOARD =====
    body += "━━━━ TOP ATTACKERS ━━━━━━━\n";
    if(attackerCount > 0) {
      for(int i=0; i<min(3, attackerCount); i++) {
        char topMac[18]; char topTarget[18];
        macToChar(attackers[i].mac, topMac);
        macToChar(attackers[i].targetNetwork, topTarget);
        String topName = getRouterName(attackers[i].targetNetwork);
        
        if(i==0) body += "🥇 ";
        else if(i==1) body += "🥈 ";
        else if(i==2) body += "🥉 ";
        
        body += String(i+1); body += ". ";
        body += topMac; body += "\n";
        body += "   Target: "; body += topName; body += "\n";
        body += "   Deauths: "; body += String(attackers[i].deauthCount);
        body += " | Intensity: "; body += String(attackers[i].intensityScore); body += "/100\n";
        
        // Mini intensity bar
        body += "   [";
        int topBars = map(attackers[i].intensityScore, 0, 100, 0, 5);
        for(int b=0; b<5; b++) {
          if(b < topBars) body += "█";
          else body += "░";
        }
        body += "]\n\n";
      }
    } else {
      body += "   No active attackers\n\n";
    }
    
    // SYSTEM INFO
    body += "━━━━ SYSTEM INFO ─────────\n";
    body += "🤖 Device: KABILAN HUNTER\n";
    body += "⚙️ Alert Threshold: "; body += String(ALERT_THRESHOLD); body += " deauths\n";
    body += "⚙️ Rate Threshold: "; body += String(RATE_THRESHOLD); body += "/s\n";
    body += "⚙️ Detection Window: "; body += String(WINDOW/1000); body += "s\n";
    body += "⏱️ Uptime: ";
    
    unsigned long uptime = millis() / 1000;
    int hours = uptime / 3600; int minutes = (uptime % 3600) / 60; int seconds = uptime % 60;
    char uptimeStr[20]; sprintf(uptimeStr, "%02d:%02d:%02d", hours, minutes, seconds);
    body += String(uptimeStr); body += "\n\n";
    
    body += "⚠️ THIS IS AN AUTOMATED ALERT\n";
    body += "====================================\n";
    
    message.text.content = body.c_str();
    
    if(smtp.connect(&config)){
      if(MailClient.sendMail(&smtp, &message)){
        Serial.println("✅✅✅ EMAIL SENT SUCCESSFULLY! ✅✅✅");
        emailSuccessCount++; lastEmailTime = millis(); saveStats();
      } else { Serial.println("❌❌❌ Email send failed! ❌❌❌"); }
      smtp.closeSession();
    } else { Serial.println("❌❌❌ SMTP connection failed! ❌❌❌"); }
    
  } else { Serial.println("❌❌❌ WiFi not connected! ❌❌❌"); }
  
  delay(100);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(CHANNELS[savedChannel], WIFI_SECOND_CHAN_NONE);
}

// ================= SHOW FUNCTIONS =================
void showAttackers() {
  Serial.println("\n=== ACTIVE ATTACKERS ===");
  if(attackerCount == 0) { Serial.println("No attackers detected"); return; }
  
  sortAttackersByIntensity();
  
  for(int i=0; i<attackerCount; i++) {
    AttackPattern pattern = detectPattern(i);
    String severity = getAttackSeverity(attackers[i].deauthCount, attackers[i].currentRate, attackers[i].rssiAvg);
    char targetStr[18]; macToChar(attackers[i].targetNetwork, targetStr);
    String networkName = getRouterName(attackers[i].targetNetwork);
    
    Serial.print(String(i+1) + ". "); Serial.print(attackers[i].macStr);
    Serial.print(" ("); Serial.print(attackers[i].vendor); Serial.print(")");
    if(attackers[i].isSpoofing) Serial.print(" [SPOOFING]");
    Serial.print("\n   → Target: ");
    if(networkName.length() > 0) Serial.print(networkName); else Serial.print("Hidden");
    Serial.print(" CH:"); Serial.print(attackers[i].targetChannel);
    Serial.print(" | Sev: "); Serial.print(severity);
    Serial.print(" | Deauths: "); Serial.print(attackers[i].deauthCount);
    Serial.print(" | Rate: "); Serial.print(attackers[i].currentRate); Serial.println("/s");
    
    // Show duration and intensity
    unsigned long duration = attackers[i].attackDuration;
    int mins = duration / 60; int secs = duration % 60;
    Serial.print("   ⏱️ Duration: ");
    if(mins > 0) { Serial.print(mins); Serial.print("m "); }
    Serial.print(secs); Serial.print("s");
    Serial.print(" | 🔥 Intensity: ");
    Serial.print(attackers[i].intensityScore);
    Serial.println("/100");
  }
}

void showStats() {
  Serial.println("\n=== KABILAN HUNTER STATS ===");
  Serial.print("Networks: "); Serial.println(routerCount);
  Serial.print("Attackers: "); Serial.println(attackerCount);
  Serial.print("Deauths: "); Serial.println(totalDeauths);
  Serial.print("Alerts: "); Serial.println(confirmedAttacks);
  Serial.print("Email Success: "); Serial.println(emailSuccessCount);
  if(lastEmailTime > 0) {
    unsigned long lastEmailSec = (millis() - lastEmailTime) / 1000;
    Serial.print("Last Email: "); Serial.print(lastEmailSec); Serial.println("s ago");
  }
}

void showEmailStatus() {
  Serial.println("\n=== EMAIL STATUS ===");
  Serial.print("Success: "); Serial.println(emailSuccessCount);
  if(lastEmailTime > 0) {
    unsigned long lastEmailSec = (millis() - lastEmailTime) / 1000;
    Serial.print("Last Email: "); Serial.print(lastEmailSec); Serial.println("s ago");
  }
}

void showBuzzerStatus() {
  Serial.println("\n=== BUZZER TEST ===");
  Serial.println("Testing buzzer...");
  for(int i=0; i<3; i++){ digitalWrite(BUZZER_PIN, HIGH); delay(200); digitalWrite(BUZZER_PIN, LOW); delay(200); }
  Serial.println("✅ Buzzer OK");
}

void showOLEDStatus() {
  Serial.println("\n=== OLED STATUS ===");
  Serial.println("OLED working");
  Serial.print("Page: "); Serial.println(oledPage + 1);
}

void showThreshold() {
  Serial.println("\n=== THRESHOLDS ===");
  Serial.print("Alert: "); Serial.print(ALERT_THRESHOLD); Serial.println(" deauths");
  Serial.print("Rate: "); Serial.print(RATE_THRESHOLD); Serial.println("/s");
  Serial.print("Window: "); Serial.print(WINDOW / 1000); Serial.println("s");
}

void changeThreshold() {
  Serial.println("\n=== CHANGE THRESHOLD ===");
  Serial.print("Current: "); Serial.println(ALERT_THRESHOLD);
  Serial.println("Enter new (15-50): ");
  unsigned long timeout = millis() + 10000;
  while(!Serial.available() && millis() < timeout) delay(100);
  if(Serial.available()) {
    int newThreshold = Serial.parseInt();
    if(newThreshold >= 15 && newThreshold <= 50) {
      ALERT_THRESHOLD = newThreshold;
      Serial.print("✅ Updated to: "); Serial.println(ALERT_THRESHOLD);
    } else Serial.println("❌ Invalid! Use 15-50");
  }
  while(Serial.available()) Serial.read();
}

void clearAttackers() { attackerCount = 0; confirmedAttacks = 0; Serial.println("\n✅ Attackers cleared"); }
void saveConfig() { prefs.begin("hunter", false); prefs.putInt("alertThreshold", ALERT_THRESHOLD); prefs.putBool("silentMode", silentMode); prefs.end(); }
void loadConfig() { prefs.begin("hunter", true); ALERT_THRESHOLD = prefs.getInt("alertThreshold", ALERT_THRESHOLD); silentMode = prefs.getBool("silentMode", silentMode); prefs.end(); }

void showHelp() {
  Serial.println("\n=== KABILAN HUNTER COMMANDS ===");
  Serial.println("s  - Show statistics");
  Serial.println("a  - List attackers");
  Serial.println("e  - Email status");
  Serial.println("b  - Test buzzer");
  Serial.println("o  - OLED status");
  Serial.println("t  - Show thresholds");
  Serial.println("c  - Change threshold");
  Serial.println("q  - Toggle Silent Mode");
  Serial.println("n  - Scan nearby networks");
  Serial.println("m  - Test email");
  Serial.println("x  - Clear attackers");
  Serial.println("r  - Reset all stats");
  Serial.println("v  - Save stats");
  Serial.println("l  - Load stats");
  Serial.println("h  - Show help");
  Serial.println("================================");
}

// ================= SERIAL COMMANDS =================
void serialCommands(){
  if(!Serial.available()) return;
  char c = Serial.read();
  while(Serial.available()) Serial.read();
  switch(c){
    case 's': showStats(); break; case 'a': showAttackers(); break; case 'e': showEmailStatus(); break;
    case 'b': showBuzzerStatus(); break; case 'o': showOLEDStatus(); break; case 't': showThreshold(); break;
    case 'c': changeThreshold(); break; case 'q': toggleSilentMode(); break; case 'n': showNearbyNetworks(); break;
    case 'm': testEmail(); break; case 'x': clearAttackers(); break; case 'r': resetAllStats(); break;
    case 'v': saveStats(); break; case 'l': loadStats(); break; case 'h': showHelp(); break;
    default: Serial.println("Unknown command. Type 'h' for help");
  }
}

// ================= SETUP =================
void setup(){
  Serial.begin(115200); delay(1000);
  Serial.println("\n\n=========================");
  Serial.println("   KABILAN HUNTER");
  Serial.println("=========================");
  Serial.println("🔥 NEW FEATURES:");
  Serial.println("✓ Attack Intensity Score");
  Serial.println("✓ Top Attackers Leaderboard");
  Serial.println("✓ Attack Duration Tracking");
  Serial.println("=========================");
  Serial.println("✓ Type 'q' to toggle mode");
  Serial.println("✓ Type 'h' for commands");
  Serial.println("✓ Type 'm' to test email");
  Serial.println("=========================");
  pinMode(BUZZER_PIN, OUTPUT);
  loadStats(); loadConfig();
  initOLED(); setupWiFi();
  wifi_country_t country = {"US",1,13,WIFI_COUNTRY_POLICY_MANUAL};
  esp_wifi_set_country(&country);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(sniffer);
  esp_wifi_set_channel(CHANNELS[0], WIFI_SECOND_CHAN_NONE);
  lastPageChange = millis();
  Serial.print("\n✅ READY - "); Serial.println(silentMode ? "Silent Mode (only attacks)" : "Verbose Mode");
}

// ================= LOOP =================
void loop(){
  serialCommands();
  if(millis() - lastChannelHop > CHANNEL_HOP_TIME){
    currentChannel = (currentChannel + 1) % NUM_CHANNELS;
    esp_wifi_set_channel(CHANNELS[currentChannel], WIFI_SECOND_CHAN_NONE);
    lastChannelHop = millis();
  }
  processEvent(); periodicScan(); powerManagement();
  static unsigned long timer = millis();
  if(millis()-timer > WINDOW){ deauthCount = 0; timer = millis(); }
  static unsigned long oledTimer = 0;
  if(millis() - oledTimer > 500) { oledTimer = millis(); updateDisplay(); attackOngoing = false; }
  static unsigned long lastAutoSave = 0;
  if(millis() - lastAutoSave > 3600000) { lastAutoSave = millis(); saveStats(); }
}
