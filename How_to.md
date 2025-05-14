# Wi-Fi Beacon Frame Synchronization

This program captures Wi-Fi beacon frames to synchronize time between two devices: a master and a slave. The program requires setting the Wi-Fi card to monitor mode to passively capture frames. 

## Requirements

To compile the code, you will need:

- A C compiler, such as `gcc`
- `libpcap` for packet capture
- `sudo` privileges to enable monitor mode

## Steps for Setting Up and Running the Program

### 1. Set Wi-Fi Card to Monitor Mode

To capture beacon frames, set your Wi-Fi card to monitor mode. This will temporarily disable your internet connection,this 
is done automatically when running the programs

1. **Check Wi-Fi card details:**
   - Run `iwconfig` in the terminal to identify your device name, typically in the form `wlp0s20f3`.
   - Confirm the mode shows as `Managed`, meaning it's not yet in monitor mode.

2. **Identify the MAC address of your gateway:**
   - Run `arp -a` to list network connections. Locate your gateway’s MAC address, which is required for filtering frames.

> **Note:** The device will not have internet connectivity while in monitor mode.

### 2. Configure the Program Files

In both `sender.h` and `receiver.c`, make these changes:
   - Update `device_name` and `device_name_mon` with your Wi-Fi device name and its monitor-mode equivalent.
   - Update the MAC address within the `filter_exp[]` array.
   - Modify `BROADCAST_IP` as needed.

### 3. Compile the Programs

Compile the sender and receiver programs on the respective devices.

- On the master device:
  ```bash
  gcc sender.c -o sender -lpcap

On the slave device:
  
  make

### 4.Run the Programs
Run sender on the master device:

 sudo ./sender

Run receiver on the slave device:

 sudo ./receiver

### Note : After completing the process, return the Wi-Fi card to managed mode to restore internet connectivity :

   sudo airmon-ng stop <your_monitor_device_name>

