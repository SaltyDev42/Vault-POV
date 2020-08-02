#!/bin/bash

cd ansible
ansible-playbook -i hosts site.yml

## Leader Vault
LEADER_VAULT=https://vault0-private.${base_fqdn}:8200

THRESHOLD=${key_threshold}
KEYSHARE=${key_share}

## Capture output
OUTPUT=$(VAULT_ADDR=$LEADER_VAULT vault operator init -key-shares=$KEYSHARE -key-threshold=$THRESHOLD)

## Filter Ooutput
TOKEN=$(grep Unseal <<< $OUTPUT | awk '{print $4}')
ROOT=$(grep Initial <<< $OUTPUT | awk '{print $4}')

## Unseal vault
VAULT_ADDR=$LEADER_VAULT vault operator unseal $TOKEN

for i in `seq 0 $((${nvault_instances}-1))`; do
    echo VAULT_ADDR=https://vault$i-private.${base_fqdn}:8200 vault operator raft join $LEADER_VAULT
    echo VAULT_ADDR=https://vault$i-private.${base_fqdn}:8200 vault operator unseal $TOKEN
done

echo UNSEAL TOKEN: $TOKEN
echo ROOT   TOKEN: $ROOT
