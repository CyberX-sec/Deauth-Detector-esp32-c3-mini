#include <WiFi.h>
#include <WebServer.h>
#include "esp_wifi.h"

// Custom MAC header structure
typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t addr1[6]; // Receiver
  uint8_t addr2[6]; // Transmitter
  uint8_t addr3[6]; // BSSID
  uint8_t seq_ctrl[2];
} wifi_ieee80211_mac_hdr_t;

// Configuration
#define SERIAL_OUTPUT_INTERVAL 1000
#define LED_BLINK_TIME 5000
#define LED_PIN 8
#define DEFAULT_CHANNEL 10
#define AP_SSID "Cipher"
#define AP_PASS "CyberX123"
#define MAX_NETWORKS 20

typedef struct {
  String ssid;
  String bssid;
  int channel;
  int rssi;
} NetworkInfo;

wifi_promiscuous_filter_t filt = {
  .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

NetworkInfo networks[MAX_NETWORKS];
int networkCount = 0;
int current_channel = DEFAULT_CHANNEL;
volatile unsigned int deauth_count = 0;
volatile unsigned long last_deauth = 0;
String web_log = "";
WebServer server(80);

String formatMacAddress(const uint8_t* mac) {
  char buf[20];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

String getTimeString() {
  unsigned long seconds = millis() / 1000;
  unsigned long minutes = seconds / 60;
  unsigned long hours = minutes / 60;
  seconds %= 60;
  minutes %= 60;
  char buf[20];
  sprintf(buf, "%02lu:%02lu:%02lu", hours, minutes, seconds);
  return String(buf);
}

void wifi_sniffer_packet_handler(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_mac_hdr_t* hdr = (wifi_ieee80211_mac_hdr_t*)pkt->payload;

  // Network Discovery
  if (type == WIFI_PKT_MGMT && pkt->payload[0] == 0x80) {
    String bssid = formatMacAddress(hdr->addr3);
    int channel = pkt->rx_ctrl.channel;
    int rssi = pkt->rx_ctrl.rssi;
    
    // Extract SSID
    String ssid = "";
    uint8_t* ptr = pkt->payload + 36;
    uint8_t ssid_len = *(ptr + 1);
    if (ssid_len > 0 && ssid_len <= 32) {
      char ssid_buf[33];
      memcpy(ssid_buf, ptr + 2, ssid_len);
      ssid_buf[ssid_len] = '\0';
      ssid = String(ssid_buf);
    } else {
      ssid = "<hidden>";
    }

    // Update or add network
    bool exists = false;
    for (int i = 0; i < networkCount; i++) {
      if (networks[i].bssid == bssid) {
        networks[i].rssi = rssi;
        networks[i].channel = channel;
        exists = true;
        break;
      }
    }
    
    if (!exists && networkCount < MAX_NETWORKS) {
      networks[networkCount++] = {ssid, bssid, channel, rssi};
    }
  }

  // Deauth Detection
  if (type == WIFI_PKT_MGMT && pkt->payload[0] == 0xC0) {
    deauth_count++;
    last_deauth = millis();
    
    String attacker = formatMacAddress(hdr->addr2);
    String victim = formatMacAddress(hdr->addr1);
    String entry = "[" + getTimeString() + "] DEAUTH " + attacker + " -> " + victim + " (Ch " + String(pkt->rx_ctrl.channel) + ")\n";
    web_log = entry + web_log;
    
    if (web_log.length() > 1000) {
      web_log = web_log.substring(0, 800);
    }
    
    Serial.println(entry);
  }
}

String generateNetworkTable() {
  String table = "";
  for (int i = 0; i < networkCount; i++) {
    int signalWidth = map(networks[i].rssi, -100, -50, 0, 100);
    signalWidth = constrain(signalWidth, 0, 100);
    
    table += "<tr>";
    table += "<td>" + networks[i].ssid + "</td>";
    table += "<td>" + networks[i].bssid + "</td>";
    table += "<td>" + String(networks[i].channel) + "</td>";
    table += "<td><div class='signal'><div class='signal-bar'><div class='signal-level' style='width:" + String(signalWidth) + "%;'></div></div>" + String(networks[i].rssi) + " dBm</div></td>";
    table += "</tr>";
  }
  return table;
}

void handleRoot() {
  String html = R"rawliteral(
<!DOCTYPE html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Security Monitor</title>
  <style>
    :root {
      --dark: #0f0f12;
      --darker: #09090c;
      --accent: #6a0dad;
      --neon: #9d4edd;
      --text: #e0e0e0;
      --alert: #d32f2f;
    }
    body {
      font-family: 'Segoe UI', sans-serif;
      background-color: var(--dark);
      color: var(--text);
      margin: 0;
      padding: 20px;
    }
    .container {
      max-width: 900px;
      margin: 0 auto;
      background-color: var(--darker);
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 0 20px rgba(106,13,173,0.2);
      border: 1px solid #2a2a35;
    }
    h1 {
      color: var(--neon);
      text-align: center;
      margin-bottom: 20px;
    }
    .alert {
      background: var(--alert);
      color: white;
      padding: 15px;
      border-radius: 6px;
      margin-bottom: 20px;
      animation: pulse 2s infinite;
      text-align: center;
    }
    @keyframes pulse {
      0% { opacity: 0.8; }
      50% { opacity: 1; }
      100% { opacity: 0.8; }
    }
    .control-panel {
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      background: rgba(20,20,30,0.7);
      padding: 15px;
      border-radius: 6px;
    }
    select, button {
      padding: 10px 15px;
      border-radius: 4px;
      font-size: 14px;
    }
    select {
      background: #1a1a25;
      color: var(--text);
      border: 1px solid #3a3a45;
      flex-grow: 1;
    }
    button {
      background: var(--accent);
      color: white;
      border: none;
      cursor: pointer;
      transition: all 0.3s;
      min-width: 120px;
    }
    button:hover {
      background: var(--neon);
    }
    .network-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }
    .network-table th {
      background: #1a1a25;
      color: var(--neon);
      padding: 12px;
      text-align: left;
    }
    .network-table td {
      padding: 12px;
      border-bottom: 1px solid #2a2a35;
    }
    .network-table tr:nth-child(even) {
      background: rgba(30,30,40,0.5);
    }
    .network-table tr:hover {
      background: rgba(106,13,173,0.1);
    }
    .signal {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .signal-bar {
      height: 10px;
      background: #333;
      border-radius: 5px;
      overflow: hidden;
      flex-grow: 1;
    }
    .signal-level {
      height: 100%;
      background: linear-gradient(90deg, #ff3e3e, #f7d060, #6aef5e);
    }
    .status {
      display: flex;
      justify-content: space-between;
      margin-top: 20px;
      font-size: 14px;
      color: #aaa;
    }
    .log {
      background: rgba(10,10,10,0.8);
      padding: 15px;
      border-radius: 6px;
      margin-top: 20px;
      max-height: 200px;
      overflow-y: auto;
      font-family: monospace;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>Network Security Monitor</h1>
    
    %DEAUTH_ALERT%
    
    <div class="control-panel">
      <select id="channel">
        <option value="1">Channel 1 (2.412 GHz)</option>
        <option value="2">Channel 2 (2.417 GHz)</option>
        <option value="3">Channel 3 (2.422 GHz)</option>
        <option value="4">Channel 4 (2.427 GHz)</option>
        <option value="5">Channel 5 (2.432 GHz)</option>
        <option value="6">Channel 6 (2.437 GHz)</option>
        <option value="7">Channel 7 (2.442 GHz)</option>
        <option value="8">Channel 8 (2.447 GHz)</option>
        <option value="9">Channel 9 (2.452 GHz)</option>
        <option value="10">Channel 10 (2.457 GHz)</option>
        <option value="11">Channel 11 (2.462 GHz)</option>
        <option value="12">Channel 12 (2.467 GHz)</option>
        <option value="13">Channel 13 (2.472 GHz)</option>
      </select>
      <button onclick="changeChannel()">Set Channel</button>
    </div>
    
    <table class="network-table">
      <thead>
        <tr>
          <th>SSID</th>
          <th>MAC</th>
          <th>Channel</th>
          <th>Signal Strength</th>
        </tr>
      </thead>
      <tbody id="network-data">
        %NETWORK_DATA%
      </tbody>
    </table>
    
    <div class="log" id="log">
      %LOG%
    </div>
    
    <div class="status">
      <div>Deauth Attacks : <span id="deauth-count">%DEAUTH_COUNT%</span></div>
      <div>Current Channel: <span>%CURRENT_CHANNEL%</span></div>
      <div>Mady by : Van De Cipher</div>
      
    </div>
  </div>

  <script>
    document.getElementById('channel').value = '%CURRENT_CHANNEL%';
    
    function changeChannel() {
      const channel = document.getElementById('channel').value;
      fetch('/setchannel?channel=' + channel)
        .then(response => {
          if (response.ok) {
            location.reload();
          }
        });
    }

    // Auto-refresh every 3 seconds
    setTimeout(() => { location.reload(); }, 6000);
  </script>
</body>
</html>
  )rawliteral";

  String deauth_alert = "";
  if (millis() - last_deauth < LED_BLINK_TIME) {
    deauth_alert = "<div class='alert'>DEAUTH ATTACK DETECTED!</div>";
  }
  
  html.replace("%DEAUTH_ALERT%", deauth_alert);
  html.replace("%DEAUTH_COUNT%", String(deauth_count));
  html.replace("%CURRENT_CHANNEL%", String(current_channel));
  html.replace("%NETWORK_DATA%", networkCount > 0 ? generateNetworkTable() : "<tr><td colspan='4'>Scanning networks... Please wait</td></tr>");
  html.replace("%LOG%", web_log.length() > 0 ? web_log : "No security events detected");
  
  server.send(200, "text/html", html);
}

void handleSetChannel() {
  if (server.hasArg("channel")) {
    current_channel = server.arg("channel").toInt();
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
    networkCount = 0; // Reset network list
    server.send(200, "text/plain", "OK");
  }
}

void wifi_sniffer_init() {
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_AP);
  esp_wifi_start();
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);

  WiFi.softAP(AP_SSID, AP_PASS);
  Serial.print("AP IP: ");
  Serial.println(WiFi.softAPIP());

  wifi_sniffer_init();

  server.on("/", handleRoot);
  server.on("/setchannel", handleSetChannel);
  server.begin();

  Serial.println("WiFi Security Monitor Ready!");
}

void loop() {
  server.handleClient();
  
  // Blink LED on deauth detection
  if (millis() - last_deauth < LED_BLINK_TIME) {
    digitalWrite(LED_PIN, millis() % 200 < 100 ? HIGH : LOW);
  } else {
    digitalWrite(LED_PIN, LOW);
  }

  // Periodic serial output
  static unsigned long last_print = 0;
  if (millis() - last_print > SERIAL_OUTPUT_INTERVAL) {
    Serial.printf("Networks: %d | Deauth: %d | Channel: %d\n", networkCount, deauth_count, current_channel);
    last_print = millis();
  }
}