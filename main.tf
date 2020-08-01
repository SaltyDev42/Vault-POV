##############################################################################
# Terraform Code to deploy 4 servers for Vault PoV 
#
# This Terraform configuration will create the following:
# 3 Linux servers running Vault 
# 1 Jumphost with Ansible installed and pre-configured
# ############################################################################

/* This is the provider block. We recommend pinning the provider version to
a known working version. If you leave this out you'll get the latest
version. */

provider "aws" {
  version = "= 2.17.0"
  region  = var.region
}

resource "aws_vpc" "pov" {
  cidr_block       = var.address_space
#  enable_dns_hostnames = "true"
  tags = {
    Name = "${var.prefix}-pov-vpc"
  }
}

resource "aws_subnet" "subnet" {
  vpc_id     = aws_vpc.pov.id
  availability_zone = "${var.region}a"
  cidr_block = var.subnet_prefix

  tags = {
    Name = "${var.prefix}-pov-subnet"
  }
}

resource "aws_internet_gateway" "main-gw" {
    vpc_id = aws_vpc.pov.id
}

resource "aws_route_table" "main-public" {
    vpc_id = aws_vpc.pov.id
    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.main-gw.id
    }
}

resource "aws_route_table_association" "main-public-1-a" {
    subnet_id = aws_subnet.subnet.id
    route_table_id = aws_route_table.main-public.id
}

resource "aws_security_group" "pov-sg" {
  name        = "${var.prefix}-sg"
  description = "Vault Security Group"
  vpc_id      = aws_vpc.pov.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self = true
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "tls_private_key" "serverkey" {
  algorithm = "RSA"
}

locals {
  ssh_idkey = "${var.prefix}-ssh-key.pem"
}

resource "aws_key_pair" "serverkey" {
  key_name   = local.ssh_idkey
  public_key = tls_private_key.serverkey.public_key_openssh
}

resource "aws_instance" "vault" {
  count         = var.nvault_instance
  ami           = var.awsami
  instance_type = var.vm_size
  subnet_id     = aws_subnet.subnet.id
  vpc_security_group_ids = [aws_security_group.pov-sg.id]
  associate_public_ip_address = "true"
  key_name = aws_key_pair.serverkey.key_name

  tags = {
    Name = "${var.prefix}-vault${count.index}"
    TTL = "720"
    owner = "${var.prefix}"
  }

  connection {
    type = "ssh"
    user = var.user
    private_key = tls_private_key.serverkey.private_key_pem
    timeout = "3m"
    host = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname vault${count.index}.ec2.internal",
      "echo ${var.id_rsapub} >> /home/${var.user}/.ssh/authorized_keys",

      # CENTOS
      "sudo yum install unzip -y",
      "sudo yum install dnsmasq -y",
      
      # ubuntu
      # "sudo apt update",
      # "sudo apt install unzip",
      # "sudo apt install dnsmasq",
    ]
  }
}

resource "aws_route53_record" "vault_private" {
  count   = var.nvault_instance
  zone_id = var.hostedzoneid
  name    = "vault${count.index}-private.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.vault[count.index].private_ip]
}
resource "aws_route53_record" "vault_pub" {
  count   = var.nvault_instance
  zone_id = var.hostedzoneid
  name    = "vault${count.index}.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.vault[count.index].public_ip]
}

resource "aws_elb" "elb_vault" {
  name      = "${var.prefix}-elb"
  instances = aws_instance.vault[*].id
  subnets   = [aws_subnet.subnet.id]

  tags = {
    Name = "${var.prefix}-vaultelb"
    TTL = "720"
    owner = "${var.prefix}"
  }

  listener {
    instance_port      = 8200
    instance_protocol  = "TCP"
    lb_port            = 443
    lb_protocol        = "TCP"
  }
}

resource "aws_route53_record" "vault" {
  zone_id   = var.hostedzoneid
  name      = "vault.${var.base_fqdn}"
  type      = "A"

  alias {
    name                   = aws_elb.elb_vault.dns_name
    zone_id                = aws_elb.elb_vault.zone_id
    evaluate_target_health = true
  }
}

## Public keys to SSH on jumphost
locals {
  sshpub = [
    var.jba_key_pub,
    var.gdo_key_pub,
    var.jpa_key_pub,
    var.jye_key_pub,
    var.aso_key_pub,
    var.cla_key_pub
  ]
}

resource "aws_instance" "jumphost" {
  ami           = var.awsami
  instance_type = "t3.medium"
  subnet_id     = aws_subnet.subnet.id
  vpc_security_group_ids = [aws_security_group.pov-sg.id]
  associate_public_ip_address = "true"
  key_name = aws_key_pair.serverkey.key_name

  tags = {
    Name = "${var.prefix}-jumphost"
    TTL = "720"
    owner = "${var.prefix}"
  }

  connection {
    type = "ssh"
    user = var.user
    timeout = "3m"
    private_key = tls_private_key.serverkey.private_key_pem
    host = self.public_ip
  }

  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname jumphost.ec2.internal",
      # centos equivalent
      "sudo yum install epel-release centos-release-ansible-29 -y",
      "sudo yum install python3 unzip ansible ansible certbot git python3-certbot-dns-route53 -y",

      "sudo yum install emacs-nox bind-utils nmap",
      # "sudo certbot certonly -n -m ${var.certbot_email} -d '*.${var.base_fqdn}' --dns-${var.dnstype} --agree-tos",
      
      # ubuntu equivalent
      # "sudo apt-add-repository ppa:ansible/ansible -y",
      # "sudo apt-get update",
      # "sudo apt-get install ansible -y",
      # "sudo apt install unzip",
      # "sudo apt install python-pip -y",

      "pip install netaddr",
      "chmod 400 ~/.ssh/id_rsa",
      "mkdir -vp ~/ansible/roles",
      "git clone https://github.com/skulblaka24/ansible-vault.git ~/ansible/roles/ansible-vault",
    ]
  }
 
  provisioner "file" {
    source      = "ansible_playbook/.ssh"
    destination = "/home/${var.user}"
  }
  provisioner "file" {
    source      = "ansible_playbook/files"
    destination = "/home/${var.user}/ansible/files"
  }
  provisioner "file" {
    source      = "ansible_playbook/site.yml"
    destination = "/home/${var.user}/ansible/site.yml"
  }
  provisioner "file" {
    content     = templatefile("ansible_playbook/hosts.tpl", {
      nvault_instance = var.nvault_instance,
      vault_instances = aws_route53_record.vault_private
    })
    destination = "/home/${var.user}/ansible/hosts"
  }
  provisioner "file" {
    content = templatefile("ansible_playbook/ansible.cfg.tpl", {
      user = var.user,
    })
    destination = "/home/${var.user}/ansible/ansible.cfg"
  }

  ## This must be put last
  ## Do not change the position of this provisioner
  provisioner "file" {
    content = templatefile("authorized_keys.tpl", {
      keys = local.sshpub
    })
    destination = "/home/${var.user}/.ssh/authorized_keys"
  }
}

resource "aws_route53_record" "jumphost" {
  zone_id = var.hostedzoneid
  name    = "jumphost.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.jumphost.public_ip]
}

resource "aws_route53_record" "jumphost_private" {
  zone_id = var.hostedzoneid
  name    = "jumphost-private.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.jumphost.private_ip]
}


##### AWX WIP


# resource "aws_instance" "awx" {
#   ami           = var.awsami
#   instance_type = "t3.2xlarge"
#   subnet_id     = aws_subnet.subnet.id
#   vpc_security_group_ids = [aws_security_group.pov-sg.id]
#   associate_public_ip_address = "true"
#   key_name = aws_key_pair.serverkey.key_name
#   tags = {
#     Name = "${var.prefix}-awx"
#     TTL = "720"
#     owner = "${var.prefix}"
#   }
#   connection {
#     type = "ssh"
#     user = "${var.user}"
#     private_key = tls_private_key.serverkey.private_key_pem
#     host = self.public_ip
#   }

#   provisioner "remote-exec" {
#     inline = [
#       "sudo yum update -y",
#       "sudo yum install podman -y"
#       "podman pull ansible/awx"
#     ]
#   }
# }
