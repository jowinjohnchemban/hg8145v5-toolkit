# Home Assistant

Home Assistant on the same LAN reads the modem's HTTP API directly. No cloud, no relay, no
account, nothing exposed to the internet. HA polls; the modem keeps no history (HA's recorder does).

Replace `<modem>` with the modem's LAN address (the service also advertises itself over mDNS as
`_hg8145v5-mcp._tcp`). Port is `8099` unless `API_PORT` was changed.

```yaml
# configuration.yaml
rest:
  - resource: http://<modem>:8099/api/metrics
    scan_interval: 30
    sensor:
      - name: "Modem uptime"
        value_template: "{{ value_json.system.uptime_seconds | int }}"
        unit_of_measurement: "s"
        device_class: duration
      - name: "Modem CPU busy"
        value_template: "{{ value_json.system.cpu_busy_percent }}"
        unit_of_measurement: "%"
      - name: "Modem free memory"
        value_template: "{{ (value_json.system.mem_free_kb / 1024) | round(0) }}"
        unit_of_measurement: "MB"
      - name: "Modem Wi-Fi clients"
        value_template: "{{ value_json.wifi_clients | sum(attribute='clients') }}"
      - name: "Modem tracked connections"
        value_template: "{{ value_json.connections.conntrack_count }}"
      - name: "Modem free flash"
        value_template: >-
          {{ (value_json.storage | selectattr('mount','eq','/mnt/jffs2')
              | map(attribute='free_kb') | first / 1024) | round(1) }}
        unit_of_measurement: "MB"
    binary_sensor:
      - name: "Modem VoIP registered"
        value_template: "{{ value_json.voice_registration.ok }}"
        device_class: connectivity
      - name: "Modem br0 up"
        value_template: >-
          {{ (value_json.ifaces | selectattr('name','eq','br0') | first).up }}
        device_class: connectivity
```

Traffic rates: add `rx_bytes`/`tx_bytes` of `br0` as sensors with `state_class: total_increasing`
and `device_class: data_size`, then use a Derivative or Statistics helper for throughput.

## Optional write actions

Only if you want HA to trigger them. The HTTP write guards allow plain API clients (HA included)
but not browsers. Set `API_WRITE_TOKEN` in the service environment and send it as a Bearer token.

```yaml
rest_command:
  modem_kick_client:
    url: http://<modem>:8099/api/tools/wifi_kick_client
    method: post
    content_type: application/json
    headers:
      Authorization: !secret modem_api_bearer   # "Bearer <token>", kept in HA secrets.yaml
    payload: '{"interface":"{{ interface }}","mac":"{{ mac }}"}'
```

`reboot_modem` is deliberately not given a ready-made HA action. If you add one, keep it behind a
confirmation in the HA UI; the modem refuses it anyway unless the body has `"confirm":"REBOOT"`.

Keep the token in HA's `secrets.yaml`, never in this repo.
