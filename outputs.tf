##############################################################################
# Outputs File
#
# Expose the outputs you want your users to see after a successful
# `terraform apply` or `terraform output` command. You can add your own text
# and include any data from the state file. Outputs are sorted alphabetically;
# use an underscore _ to move things to the bottom. In this example we're
# providing instructions to the user on how to connect to their own custom
# demo environment.
#
# output "Vault_Server_URL" {
#   value = "http://${aws_instance.vault-server.public_ip}:8200"
# }
# output "MySQL_Server_FQDN" {
#   value = "${aws_db_instance.vault-demo.address}"
# }
output "Instructions" {
  value = <<EOF

# Connect to your Linux Virtual Machine
#
# Run the command below to SSH into your server. You can also use PuTTY or any
# other SSH client. Your SSH key is already loaded for you.

ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.vault1.public_ip}
ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.vault2.public_ip}
ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.consul1.public_ip}
ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.consul2.public_ip}
ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.consul3.public_ip}
ssh -i ${module.ssh-keypair-aws.private_key_filename} ubuntu@${aws_instance.ansible.public_ip}
EOF
}
