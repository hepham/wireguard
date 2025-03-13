# Wireguard VPN Dashboard

A containerized Wireguard VPN server with web dashboard for easy configuration and management.

## Features

- Easy-to-use web dashboard for managing Wireguard VPN
- Client configuration via QR codes
- User management interface
- Traffic statistics and monitoring

## Requirements

- Ubuntu/Debian (recommended) or other Linux distribution
- Open ports: 51820/udp (Wireguard) and 10086/tcp (Dashboard)

## Quick Start


If you don't have Docker installed, use the provided script:


### 1. Clone the repository

```bash
git clone https://github.com/hepham/wireguard.git
cd wireguard-dashboard/src
```
### 2. Install wireguard
```bash
sudo chmod +x wireguard-install.sh
sudo ./wireguard-install.sh
```
Set port 51820 other default config.

### 3. Install WGDashboard

```bash
sudo chmod u+x wgd.sh
sudo ./wgd.sh install
```

### 4. Configure permissions for WireGuard

Give read and execute permission to the root of the WireGuard configuration folder. You can change the path if your configuration files are not stored in `/etc/wireguard`.

```bash
sudo chmod -R 755 /etc/wireguard
```

### 5. Run WGDashboard

```bash
./wgd.sh start
```

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
./wgd.sh stop
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

