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

  tags = {
    Name = "$(var.prefix)-vault-gw"
  }
}

resource "aws_route_table" "main-public" {
  vpc_id = aws_vpc.pov.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main-gw.id
  }

  tags = {
    Name = "${var.prefix}-vault-NAT"
  }
}

resource "aws_route_table_association" "main-public-1-a" {
  subnet_id = aws_subnet.subnet.id
  route_table_id = aws_route_table.main-public.id
}
#### WIP
# locals {
#   lb = [
#     "${var.prefix}-lb",
#     "${var.prefix}-tower-lb",
#     "${var.prefix}-awx-lb"
#   ]
# }

# resource "aws_lb" "lb" {
#   for_each = local.lb
#   name     = each.value
#   subnets   = [aws_subnet.subnet.id]
#   load_balancer_type = "network"
#   ip_address_type = "ipv4"
#   tags = {
#     Name = "${var.prefix}-lb"
#     TTL = "720"
#     owner = "${var.prefix}"
#   }
# }

resource "aws_lb" "vault" {
  name      = "${var.prefix}-lb"
  subnets   = [aws_subnet.subnet.id]
  load_balancer_type = "network"
  ip_address_type = "ipv4"
  tags = {
    Name = "${var.prefix}-lb"
    TTL = "720"
    owner = "${var.prefix}"
  }
}

resource "aws_lb" "tower" {
  name      = "${var.prefix}-tower-lb"
  subnets   = [aws_subnet.subnet.id]
  load_balancer_type = "network"
  ip_address_type = "ipv4"
  tags = {
    Name = "${var.prefix}-tower-lb"
    TTL = "720"
    owner = "${var.prefix}"
  }  
}

resource "aws_lb" "awx" {
  name      = "${var.prefix}-awx-lb"
  subnets   = [aws_subnet.subnet.id]
  load_balancer_type = "network"
  ip_address_type = "ipv4"
  tags = {
    Name = "${var.prefix}-awx-lb"
    TTL = "720"
    owner = "${var.prefix}"
  }
}

data "aws_network_interface" "vault" {
  filter {
    name = "description"
    values = ["ELB net/${aws_lb.vault.name}/*"]
  }
  filter {
    name = "vpc-id"
    values = ["${aws_vpc.pov.id}"]
  }
  filter {
    name = "status"
    values = ["in-use"]
  }
  filter {
    name = "attachment.status"
    values = ["attached"]
  }
}

data "aws_network_interface" "awx" {
  filter {
    name = "description"
    values = ["ELB net/${aws_lb.awx.name}/*"]
  }
  filter {
    name = "vpc-id"
    values = ["${aws_vpc.pov.id}"]
  }
  filter {
    name = "status"
    values = ["in-use"]
  }
  filter {
    name = "attachment.status"
    values = ["attached"]
  }
}

data "aws_network_interface" "tower" {
  filter {
    name = "description"
    values = ["ELB net/${aws_lb.tower.name}/*"]
  }
  filter {
    name = "vpc-id"
    values = ["${aws_vpc.pov.id}"]
  }
  filter {
    name = "status"
    values = ["in-use"]
  }
  filter {
    name = "attachment.status"
    values = ["attached"]
  }
}

resource "aws_security_group" "vault" {
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
    from_port   = 8200
    to_port     = 8200
    protocol    = "tcp"
    cidr_blocks = ["${data.aws_network_interface.vault.private_ip}/32"]
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    cidr_blocks = ["${data.aws_network_interface.tower.private_ip}/32"]
  }

  ingress {
    from_port   = 8443
    to_port     = 8443
    protocol    = "tcp"
    cidr_blocks = ["${data.aws_network_interface.awx.private_ip}/32"]
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}-sg"
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

## Target Group ressources will be added later
resource "aws_lb_target_group" "vault" {
  name      = "${var.prefix}-lbtg"
  port      = 8200
  protocol  = "TCP"
  vpc_id    = aws_vpc.pov.id
  target_type = "ip"

  stickiness {
    type = "lb_cookie"
    enabled = false
  }

  health_check {
    path = "/ui"
    port = 8200
    protocol = "HTTPS"
  }
}

resource "aws_lb_target_group" "tower" {
  name      = "${var.prefix}-tower-lbtg"
  port      = 443
  protocol  = "TCP"
  vpc_id    = aws_vpc.pov.id
  target_type = "ip"

  stickiness {
    type = "lb_cookie"
    enabled = false
  }

  health_check {
    path = "/"
    port = 443
    protocol = "HTTPS"
  }
}


resource "aws_lb_target_group" "awx" {
  name      = "${var.prefix}-awx-lbtg"
  port      = 8443
  protocol  = "TCP"
  vpc_id    = aws_vpc.pov.id
  target_type = "ip"

  stickiness {
    type = "lb_cookie"
    enabled = false
  }

  health_check {
    path = "/#/login"
    port = 8443
    protocol = "HTTPS"
  }
}

resource "aws_route53_record" "vault" {
  zone_id   = var.hostedzoneid
  name      = "vault.${var.base_fqdn}"
  type      = "A"

  alias {
    name                   = aws_lb.vault.dns_name
    zone_id                = aws_lb.vault.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "awx" {
  zone_id = var.hostedzoneid
  name    = "awx.${var.base_fqdn}"
  type    = "A"

  alias {
    name                   = aws_lb.awx.dns_name
    zone_id                = aws_lb.awx.zone_id
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "tower" {
  zone_id = var.hostedzoneid
  name    = "tower.${var.base_fqdn}"
  type    = "A"

  alias {
    name                   = aws_lb.tower.dns_name
    zone_id                = aws_lb.tower.zone_id
    evaluate_target_health = true
  }
}

resource "aws_lb_listener" "awx" {
  load_balancer_arn = aws_lb.awx.arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.awx.arn
  }
}

resource "aws_lb_listener" "tower" {
  load_balancer_arn = aws_lb.tower.arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.tower.arn
  }
}

resource "aws_lb_listener" "vault" {
  load_balancer_arn = aws_lb.vault.arn
  port              = "443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vault.arn
  }
}

############BASTION###############
## Public keys to SSH on jumphost
locals {
  sshpub = [
    tls_private_key.serverkey.public_key_openssh,
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
  vpc_security_group_ids = [aws_security_group.vault.id]
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

  provisioner "file" {
    source      = "ansible_playbook/.ssh"
    destination = "/home/${var.user}"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname jumphost.ec2.internal",
      # centos equivalent
      "sudo yum install epel-release centos-release-ansible-29 -y",
      "sudo yum install python3 unzip ansible ansible certbot git python3-certbot-dns-route53 -y",

      "sudo yum install emacs-nox bind-utils nmap -y",
      # "sudo certbot certonly -n -m ${var.certbot_email} -d '*.${var.base_fqdn}' --dns-${var.dnstype} --agree-tos",

      # ubuntu equivalent
      # "sudo apt-add-repository ppa:ansible/ansible -y",
      # "sudo apt-get update",
      # "sudo apt-get install ansible -y",
      # "sudo apt install unzip",
      # "sudo apt install python-pip -y",
      "curl -LO https://releases.hashicorp.com/vault/${var.vault_vers}+ent/vault_${var.vault_vers}+ent_linux_amd64.zip",
      "unzip vault_${var.vault_vers}+ent_linux_amd64.zip",
      "sudo cp vault /usr/local/bin",
      "pip install netaddr",
      "chmod 400 ~/.ssh/id_rsa",
      "mkdir -vp ~/ansible/roles",
      "git clone https://github.com/skulblaka24/ansible-vault.git ~/ansible/roles/ansible-vault",
    ]
  }
 
  provisioner "file" {
    source      = "ansible_playbook/files"
    destination = "/home/${var.user}/ansible/files"
  }
  provisioner "file" {
    content     = templatefile("ansible_playbook/site.yml.tpl", {
      vault_version = var.vault_vers
    })
    destination = "/home/${var.user}/ansible/site.yml"
  }
  provisioner "file" {
    content     = templatefile("ansible_playbook/hosts.tpl", {
      nvault_instance = var.nvault_instance,
      fqdns = [
        for i in range(var.nvault_instance):
        "vault${i}-private.${var.base_fqdn}"
      ]
    })
    destination = "/home/${var.user}/ansible/hosts"
  }
  provisioner "file" {
    content = templatefile("ansible_playbook/ansible.cfg.tpl", {
      user = var.user,
    })
    destination = "/home/${var.user}/ansible/ansible.cfg"
  }

  provisioner "file" {
    content     = templatefile("deploy.sh.tpl", {
      base_fqdn        = var.base_fqdn
      key_share        = var.key_share
      key_threshold    = var.threshold
      nvault_instances = var.nvault_instance
    })
    destination = "/home/${var.user}/deploy.sh"
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

############VAULT###################
## Unreachable from external IPs

resource "aws_instance" "vault" {
  count         = var.nvault_instance
  ami           = var.awsami
  instance_type = var.vm_size
  subnet_id     = aws_subnet.subnet.id
  vpc_security_group_ids = [aws_security_group.vault.id]
  
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
    host = self.private_ip

    bastion_host = aws_instance.jumphost.public_ip
    bastion_private_key = tls_private_key.serverkey.private_key_pem
    bastion_user = var.user
  }
  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname vault${count.index}.ec2.internal",
      "echo ${var.id_rsapub} >> /home/${var.user}/.ssh/authorized_keys",
    ]
  }
}

resource "aws_eip" "vault" {
  count = var.nvault_instance

  instance                  = aws_instance.vault[count.index].id
  tags = {
    Name = "${var.prefix}${count.index}-eip"
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

resource "aws_lb_target_group_attachment" "vault" {
  count            = var.nvault_instance
  target_group_arn = aws_lb_target_group.vault.arn
  target_id        = aws_instance.vault[count.index].private_ip
  port             = 8200
}

##### AWX WIP

resource "aws_instance" "awx" {
  ami           = var.awsami
  instance_type = "t3.2xlarge"
  subnet_id     = aws_subnet.subnet.id
  vpc_security_group_ids = [aws_security_group.vault.id]
  associate_public_ip_address = "true"
  key_name = aws_key_pair.serverkey.key_name
  tags = {
    Name = "${var.prefix}-awx"
    TTL = "720"
    owner = "${var.prefix}"
  }
  connection {
    type = "ssh"
    user = var.user
    private_key = tls_private_key.serverkey.private_key_pem
    host = self.public_ip
  }

  provisioner "file" {
    source = "ansible_playbook/files"
    destination = "/home/${var.user}/certs"
  }

  provisioner "file" {
    source = "awx"
    destination = "/home/${var.user}/awx"
  }

  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname awx.ec2.internal",
      "echo ${var.id_rsapub} >> /home/${var.user}/.ssh/authorized_keys",
      "sudo yum install git -y",
      "sudo yum install epel-release -y",
      "sudo yum install python3 -y",

      "sudo yum install  libselinux-python3.x86_64 -y",
      "sudo yum remove python-requests -y",
      "sudo yum install ansible -y",

      "sudo curl  https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo",
      "sudo yum makecache -y",
      "sudo yum -y  install docker-ce --nobest",
      "sudo systemctl enable --now docker",
      "sudo usermod -aG docker $USER",

      "sudo pip3 install --upgrade pip",
      "sudo pip3 install -U docker docker-compose",
      "sudo ansible-playbook -i ~/awx/installer/inventory ~/awx/installer/install.yml"
    ]
  }
}

resource "aws_lb_target_group_attachment" "awx" {
  target_group_arn = aws_lb_target_group.awx.arn
  target_id        = aws_instance.awx.private_ip
  port             = 8443
}

resource "aws_route53_record" "awx-private" {
  zone_id = var.hostedzoneid
  name    = "awx-private.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.awx.private_ip]
}


#### TOWER

data "aws_ami" "rhel8" {
  owners = ["309956199498"]
  most_recent = true
  name_regex = "RHEL-8.2.0_HVM-[0-9]*-x86_64.*"
  filter {
    name = "architecture"
    values = ["x86_64"]
  }
  filter {
    name = "name"
    values = ["RHEL-8.2*"]
  }
  filter {
    name = "virtualization-type"
    values = ["hvm"]
  }
  filter {
    name = "state"
    values = ["available"]
  }
}

resource "aws_instance" "tower" {
  ami           = data.aws_ami.rhel8.image_id
  instance_type = "t3.2xlarge"
  subnet_id     = aws_subnet.subnet.id
  vpc_security_group_ids = [aws_security_group.vault.id]
  associate_public_ip_address = "true"
  key_name = aws_key_pair.serverkey.key_name
  tags = {
    Name = "${var.prefix}-tower"
    TTL = "720"
    owner = "${var.prefix}"
  }

  connection {
    type = "ssh"
    user = "ec2-user"
    private_key = tls_private_key.serverkey.private_key_pem
    host = self.public_ip
  }
  provisioner "remote-exec" {
    inline = [
      "sudo hostnamectl set-hostname tower.ec2.internal",
      "echo ${var.id_rsapub} >> /home/ec2-user/.ssh/authorized_keys",
    ]
  }
}

resource "aws_route53_record" "tower-private" {
  zone_id = var.hostedzoneid
  name    = "tower-private.${var.base_fqdn}"
  type    = "A"
  ttl     = "300"
  records = [aws_instance.tower.private_ip]
}

resource "aws_lb_target_group_attachment" "tower" {
  target_group_arn = aws_lb_target_group.tower.arn
  target_id        = aws_instance.tower.private_ip
  port             = 443
}
