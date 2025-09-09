# Wazuh-maltiverse-integration
Integrate Maltiverse using script

1. Create file custom script
   - nano /var/ossec/integrations/maltiverse-ip-check.py
2. Create custom rule
   - nano /var/ossec/etc/rules/100016-maltiverse.xml
3. Create custom decoder
   - nano /var/ossec/etc/decoders/maltiverse-custom.xml
4. Setup Cron Job
   - sudo crontab -e -u root
   - */10 * * * * /var/ossec/integrations/ maltiverse-ip-check.py
5. Restart wazuh-manager
    - sudo systemctl restart wazuh-manager

