# How to Add a New Application to the WAF System

This guide outlines the standardized process for integrating a new web application into the WAF's protection umbrella. Following these steps ensures that the new application is properly isolated and that all its traffic is routed through the WAF for inspection.

## Architecture Overview

The core principle is **micro-segmentation**. Each application (or a tightly coupled group of services like a frontend and backend) lives in its own isolated Docker network. The WAF is multi-homed, meaning it connects to its own core network and to each protected application's network, acting as a secure gateway.

---

### Step 1: Prepare the New Application

The first step is to containerize your application and configure it to run on a dedicated, isolated network with static IP addresses.

1.  **Create a `docker-compose.yml` for the app:** If one doesn't exist, create it in the application's root directory.

2.  **Define an Isolated Network:** In the app's `docker-compose.yml`, define a new bridge network. Choose a unique subnet from the private `10.99.x.0/24` range.

    ```yaml
    networks:
      my-app-net:
        name: my-app-net       # A unique name for the network
        driver: bridge
        ipam:
          driver: default
          config:
            - subnet: 10.99.13.0/24 # Choose a new, unused subnet
    ```

3.  **Assign Static IPs:** Assign static IPs from your new subnet to your application's services. This is crucial for the WAF to reliably find your application.

    ```yaml
    services:
      my-app-backend:
        # ... other service config
        networks:
          my-app-net:
            ipv4_address: 10.99.13.10 # Static IP for the backend

      my-app-frontend:
        # ... other service config
        networks:
          my-app-net:
            ipv4_address: 10.99.13.11 # Static IP for the frontend
    ```

4.  **Remove External Ports:** Ensure that no application services expose ports to the host machine. Delete all `ports` sections from your services. All access must go through the WAF.

---

### Step 2: Connect the WAF to the New App's Network

Now, you need to tell the WAF system about the new application's network so it can connect to it.

1.  **Edit `WAF/docker-compose.yml`:** Open the main docker-compose file for the WAF.

2.  **Declare the External Network:** At the bottom of the file, under the `networks:` section, add a declaration for your new application's network. It's `external` because it's defined in another compose file.

    ```yaml
    networks:
      # ... existing networks (waf-core-net, dvwa-net, etc.)

      my-app-net: # The same name you used in the app's compose file
        external: true
        name: my-app-net
    ```

3.  **Connect WAF and Mitmproxy:** Add the new network to the `networks:` list for both the `waf` and `mitmproxy` services.

    ```yaml
    services:
      waf:
        # ... other waf config
        networks:
          - waf-core-net
          - dvwa-net
          - juiceshop-net
          - hr-system-net
          - my-app-net # <-- Add your new network here

      mitmproxy:
        # ... other mitmproxy config
        networks:
          - waf-core-net
          - dvwa-net
          - juiceshop-net
          - hr-system-net
          - my-app-net # <-- And also here
    ```

---

### Step 3: Configure the WAF to Proxy the New Site

With the networking in place, the final step is to add a new "Site" configuration to the WAF's database. This tells the WAF where to forward incoming requests for a specific domain.

This is done by making a `POST` request to the WAF's API.

```bash
curl -X POST http://localhost:8001/sites/ \
-H "Content-Type: application/json" \
-H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
-d '{
  "name": "My Awesome App",
  "description": "The best app ever.",
  "backend_url": "http://10.99.13.10",
  "is_active": true,
  "is_learning": true
}'
```

*   **`backend_url`**: This **must** be the static IP and port of your application's primary entry point (usually the backend or a web server).
*   **Authorization**: You will need a valid JWT token for an admin user to perform this action.

---

### Step 4: System Startup Order

To bring everything up correctly, follow this order:

1.  **Start the Application:** Navigate to your new application's directory and run:
    ```bash
    docker-compose up -d --build
    ```
    This command also creates the shared network automatically.

2.  **Restart the WAF:** Navigate to the `WAF/` directory and run:
    ```bash
    docker-compose up -d --force-recreate --build
    ```
    The `--force-recreate` flag is important to ensure the `waf` and `mitmproxy` containers are recreated with the new network connections.

Your new application is now fully integrated and protected by the WAF.
