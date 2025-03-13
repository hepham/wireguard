# Wireguard VPN Dashboard

A containerized Wireguard VPN server with web dashboard for easy configuration and management.

## Features

- Easy-to-use web dashboard for managing Wireguard VPN
- Docker containerized for simple deployment
- Client configuration via QR codes
- User management interface
- Traffic statistics and monitoring

## Requirements

- Docker and Docker Compose
- Ubuntu/Debian (recommended) or other Linux distribution
- Open ports: 51820/udp (Wireguard) and 10086/tcp (Dashboard)

## Quick Start

### 1. Install Docker and Docker Compose (Ubuntu)

If you don't have Docker installed, use the provided script:

```bash
sudo chmod +x install_docker_ubuntu.sh
sudo ./install_docker_ubuntu.sh
```

### 2. Clone the repository

```bash
git clone https://github.com/hepham/wireguard.git
cd wireguard
```

### 3. Start the Wireguard VPN server

```bash
docker-compose up -d
```

### 4. Access the dashboard

Open your browser and navigate to:
```
http://your-server-ip:10086
```

Default login credentials:
- Username: admin
- Password: admin

**Important:** Change the default credentials immediately after first login.

## Project Structure

```
wireguard/
├── docker-compose.yml     # Docker configuration
├── env.sh                 # Environment setup script
├── img/                   # Images for the dashboard
└── src/
    ├── dashboard.py       # Main dashboard application
    ├── db/                # Database files
    ├── static/            # Static assets for the web interface
    ├── templates/         # HTML templates
    ├── wgd.sh             # Wireguard dashboard control script
    └── requirements.txt   # Python dependencies
```

## Client Setup

1. Access the dashboard at http://your-server-ip:10086
2. Navigate to the "Clients" section
3. Click "Add Client" and fill in the required information
4. Download the configuration file or scan the QR code with your Wireguard client app

## Managing the Server

### Stop the server

```bash
docker-compose down
```

### View logs

```bash
docker-compose logs -f
```

### Restart the server

```bash
docker-compose restart
```

## Troubleshooting

### Connection Issues

- Ensure ports 51820/udp and 10086/tcp are open in your firewall
- Check if the container is running: `docker ps`
- Verify logs for errors: `docker-compose logs -f`

### Dashboard Access Problems

- Verify the server IP address is correct
- Check if your network allows access to port 10086
- Ensure the container is running properly

## Security Recommendations

- Change default dashboard credentials immediately
- Use a reverse proxy with HTTPS for dashboard access
- Configure firewall rules to limit access to the dashboard
- Regularly update the container: `docker-compose pull && docker-compose up -d`

## License

This project is licensed under the MIT License - see the LICENSE file for details.
