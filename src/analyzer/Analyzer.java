/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package analyzer;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

/**
 *
 * @author asenf
 */
public class Analyzer {

    static PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;
        try {
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return device;
    }

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        boolean dump = false;
        if (args.length > 0) 
            dump=true;

        final PcapHandle handle;
        if (!dump) {
            PcapNetworkInterface device = getNetworkDevice();
            System.out.println("You chose: " + device);

            // New code below here
            if (device == null) {
                System.out.println("No device chosen.");
                System.exit(1);
            }

            // Open the device and get a handle
            int snapshotLength = 65536; // in bytes   
            int readTimeout = 50; // in milliseconds                   
            handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
        } else {
            handle = Pcaps.openOffline("dump.pcap", TimestampPrecision.NANO);
        }

        if (!dump) {
            // Set a filter to only listen for tcp packets on port 80 (HTTP)
            String filter = "tcp port 8051";
            handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

            final PcapDumper dumper = handle.dumpOpen("dump.pcap");

            // Create a listener that defines what to do with the received packets
            PacketListener listener = new PacketListener() {
                private long cnt = 0;
                
                @Override
                public void gotPacket(Packet packet) {
                    cnt++;

                    // Write packets as needed
                    try {
                        dumper.dump(packet, handle.getTimestamp());
                    } catch (NotOpenException e) {
                        e.printStackTrace();
                    }
                    
                    if ( (cnt%100) == 0 ) {
                        PcapStat stats;
                        try {
                            System.out.println("************************************************ " + cnt);
                            stats = handle.getStats();
                            System.out.println("Packets received: " + stats.getNumPacketsReceived());
                            System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
                            System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
                        } catch (PcapNativeException | NotOpenException ex) {
                            Logger.getLogger(Analyzer.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                    
                    // Override the default gotPacket() function and process packet
                    //System.out.println(handle.getTimestamp());
                    //System.out.println(packet);
                }
            };

            // Tell the handle to loop using the listener we created
            try {
                int maxPackets = 50000;
                handle.loop(maxPackets, listener);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            
            dumper.close();        
        } else {
            PcapStat stats = handle.getStats();
            System.out.println("Packets received: " + stats.getNumPacketsReceived());
            System.out.println("Packets dropped: " + stats.getNumPacketsDropped());
            System.out.println("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
        }
        
        // Cleanup when complete
        handle.close();        
    }
    
}
