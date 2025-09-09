# wazuh-slack-alert-integration

Custom slack integration on wazuh

1. Integrate Slack for agent-specific alerts
- Create custom script: /var/ossec/integrations/custom-slack
- Config ossec.conf
- Add the following configuration code inside the <ossec_config> tags:
"""
<integration>
  <name>custom-slack</name>
  <level>7</level>  <!-- Customize alert level -->
  <alert_format>json</alert_format>
</integration>
"""
- Restart wazuh-manager: sudo systemctl restart wazuh-manager

2. Integrate Slack for severity-specific alerts.
- Create custom script: /var/ossec/integrations/custom-slack-level
- Config ossec.conf
- Add the following configuration code inside the <ossec_config> tags:
"""
<integration>
  <name>custom-slack-level</name>
  <level>7</level>  <!-- Customize alert level -->
  <alert_format>json</alert_format>
</integration>
"""
- Restart wazuh-manager: sudo systemctl restart wazuh-manager