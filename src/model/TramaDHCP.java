/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import java.nio.ByteBuffer;
import java.util.UUID;

/**
 *
 * @author carli
 */
public class TramaDHCP {
    
    public final static byte[] MAGIC_COOKIE = armarMagicCookie(); // Magic cookie para DHCP 0x63825363

    private byte op; // OPCODE
    private byte htype; // Tipo de hardware
    private byte hlen; // Longitud de hardware
    private byte hops; // El cliente lo pone en cero

    private byte[] xid; // ID de la transacción
    
    private byte[] secs; // Segundos desde que el cliente hizo la solicitud
    private byte[] flags; // Bootp flags

    private byte[] ciaddr; // Dirección IP del cliente
    private byte[] yiaddr; // Dirección IP del cliente
    private byte[] siaddr; // Dirección IP del servidor se llena en DHCPOFFER y DHCPACK
    private byte[] giaddr; // Dirección IP del rely agent

    private byte[] chaddr; // Dirección MAC del cliente
    
    private byte[] sname; // Host name del servidor
    private byte[] file; //Bot file  

    private TramaDHCP(){
        xid = new byte[4];
        secs = new byte[2];
        flags = new byte[2];
        
        // Direcciones IPv4
        ciaddr = new byte[4];
        yiaddr = new byte[4];
        siaddr = new byte[4];
        giaddr = new byte[4];
        
        chaddr = new byte[16];
        
        sname = new byte[64];
        file = new byte[128];
    }

    public static TramaDHCP crearTramaDHCP(byte[] data){
        TramaDHCP encabezado = new TramaDHCP();

        int i = 0;
        
        // OP, Hardwae cliente, BOOT Flags
        encabezado.setOp(data[i++]);
        encabezado.setHtype(data[i++]);
        encabezado.setHlen(data[i++]);
        encabezado.setHops(data[i++]);

        // ID de la transaccion
        byte[] xid = new byte[4];
        for(int j=0; j < 4; j++,i++){
            xid[j] = data[i];
        }
        encabezado.setXid(xid);

        // Secs y Flags
        byte[] secs = new byte[2];
        byte[] flags = new byte[2];
        for(int idx=0, idx_1=i, idx_2=i+4; idx < 2; idx++, idx_1++, idx_2++){
            secs[idx] = data[idx_1];
            flags[idx] = data[idx_2];
        }
        i += 4; 
        encabezado.setSecs(secs);
        encabezado.setFlags(flags);

        // Direcciones IPv4
        byte[] ciaddr = new byte[4];
        byte[] yiaddr = new byte[4];
        byte[] siaddr = new byte[4];
        byte[] giaddr = new byte[4];
        for(int idx = 0,idx_1=i, idx_2 = i+4, idx_3 = i+8, idx_4 = i+12; idx < 4; idx++, idx_1++,idx_2++,idx_3++,idx_4++){
            ciaddr[idx] = data[idx_1];
            yiaddr[idx] = data[idx_2];
            siaddr[idx] = data[idx_3];
            giaddr[idx] = data[idx_4];
        }
        i += 16;
        encabezado.setCiaddr(ciaddr);
        encabezado.setYiaddr(yiaddr);
        encabezado.setSiaddr(siaddr);
        encabezado.setGiaddr(giaddr);

        // Dirección Hardware
        byte[] chaddr = new byte[16];
        for(int j=0; j < 16; j++,i++){
            chaddr[j] = data[i];
        }
        encabezado.setChaddr(chaddr);

        // Nombre del Host
        byte[] sname = new byte[64];
        for(int j=0; j < 64; j++,i++){
            sname[j] = data[i];
        }
        encabezado.setSname(sname);

        // File
        byte[] file = new byte[128];
        for(int j=0; j < 128; j++,i++){
            file[j] = data[i];
        }
        encabezado.setFile(file);

        return encabezado;
    }

    public static TramaDHCP crearDiscoverCliente(byte[] MAC){
        TramaDHCP tramaDiscover = new TramaDHCP();
        
        /// Llenar primeros 32 bytes
        Integer op = new Integer(1); // BOOT Request
        tramaDiscover.setOp(op.byteValue());

        Integer htype = new Integer(1); // Ethernet
        tramaDiscover.setHtype(htype.byteValue());

        Integer hlen = new Integer(6); // Tamaño de una dirección MAC
        tramaDiscover.setHlen(hlen.byteValue());

        Integer hops = new Integer(0);
        tramaDiscover.setHops(hops.byteValue()); // Sin banderas

        // Armar el xid
        byte[] xid = armarXID(); 
        tramaDiscover.setXid(xid);

        // Armar secs y flags
        Integer cero = new Integer(0);
        byte[] ceros_2 = new byte[2];

        for(int i=0; i < 2; i++){
            ceros_2[i] = cero.byteValue();
        }
        tramaDiscover.setSecs(ceros_2);
        tramaDiscover.setFlags(ceros_2);

        // Armar direcciones IP
        byte[] ceros_4 = new byte[4];

        for(int i=0; i < 4; i++){
            ceros_4[i] = cero.byteValue();
        }
        tramaDiscover.setCiaddr(ceros_4);
        tramaDiscover.setYiaddr(ceros_4);
        tramaDiscover.setSiaddr(ceros_4);
        tramaDiscover.setGiaddr(ceros_4);

        // Llenar dirección MAC

        return tramaDiscover;
    }

    private static byte[] armarXID(){
        UUID xid_1 = UUID.randomUUID();
        UUID xid_2 = UUID.randomUUID();
        ByteBuffer xid_t = ByteBuffer.wrap(new byte[32]);

        xid_t.putLong(xid_1.getMostSignificantBits());
        xid_t.putLong(xid_1.getLeastSignificantBits());
        xid_t.putLong(xid_2.getMostSignificantBits());
        xid_t.putLong(xid_2.getLeastSignificantBits());
    
        return xid_t.array();
    }

    private static byte[] armarMagicCookie(){
        ByteBuffer magicCookie = ByteBuffer.wrap(new byte[4]);
        magicCookie.put(new Integer(0x63).byteValue());
        magicCookie.put(new Integer(0x82).byteValue());
        magicCookie.put(new Integer(0x53).byteValue());
        magicCookie.put(new Integer(0x63).byteValue());

        return magicCookie.array();
    }

    public static byte[] crearOffer(TramaDHCP offer){
        byte[] offer_b = new byte[240];
        
        // ENCABEZADO
        offer_b[0] = offer.getOp();
        offer_b[1] = offer.getHtype();
        offer_b[2] = offer.getHlen();
        offer_b[3] = offer.getHops();

        // ID DE LA TRANSACCION
        int i = 4;
        for(int idx =0; idx < 4; i++, idx++){
            offer_b[i] = offer.getXid()[idx];
        }

        // SECS & FLAGS
        for(int idx =0; idx < 2; i++, idx++){
            offer_b[i] = offer.getSecs()[idx];
        }
        for(int idx =0; idx < 2; i++, idx++){
            offer_b[i] = offer.getFlags()[idx];
        }

        // Direcciones IP
        for(int idx = 0,idx_1=i, idx_2 = i+4, idx_3 = i+8, idx_4 = i+12; idx < 4; idx++, idx_1++,idx_2++,idx_3++,idx_4++){
            offer_b[idx_1] = offer.getCiaddr()[idx];
            offer_b[idx_2] = offer.getYiaddr()[idx];
            offer_b[idx_3] = offer.getSiaddr()[idx];
            offer_b[idx_4] = offer.getGiaddr()[idx];
        }
        i += 16;

        // DIR MAC
        for(int idx = 0; idx < 16; idx++, i++){
            offer_b[i] = offer.getChaddr()[idx];
        }

        // SNAME
        for(int idx = 0; idx < 64; idx++, i++){
            offer_b[i] = offer.getSname()[idx];
        }

        // File
        for(int idx = 0; idx < 128; idx++, i++){
            offer_b[i] = offer.getFile()[idx];
        }

        // Magic Cookie
        for(int idx = 0; idx < 4; idx++, i++){
            offer_b[i] = TramaDHCP.MAGIC_COOKIE[idx];
        }
        
        return offer_b;
    }

    public static byte[] crearRequest(){
        byte[] offer_b = new byte[240];
        
        // ENCABEZADO
        offer_b[0] = 1;
        offer_b[1] = 1;
        offer_b[2] = 6;
        offer_b[3] = 0;

        // ID DE LA TRANSACCION
        int i = 4;
        byte[] xid = armarXID();
        for(int idx =0; idx < 4; i++, idx++){
            offer_b[i] = xid[idx];
        }

        // SECS & FLAGS
        for(int idx =0; idx < 2; i++, idx++){
            offer_b[i] = 0;
        }
        for(int idx =0; idx < 2; i++, idx++){
            offer_b[i] = 0;
        }

        // Direcciones IP
        for(int idx = 0,idx_1=i, idx_2 = i+4, idx_3 = i+8, idx_4 = i+12; idx < 4; idx++, idx_1++,idx_2++,idx_3++,idx_4++){
            offer_b[idx_1] = 0;
            offer_b[idx_2] = 0;
            offer_b[idx_3] = 0;
            offer_b[idx_4] = 0;
        }
        i += 16;

        // DIR MAC
        for(int idx = 0; idx < 6; idx++, i++){
            offer_b[i] = 2;
        }
        for(int idx = 0; idx < 10; idx++, i++){
            offer_b[i] = 0;
        }

        // SNAME
        for(int idx = 0; idx < 64; idx++, i++){
            offer_b[i] = 0;
        }

        // File
        for(int idx = 0; idx < 128; idx++, i++){
            offer_b[i] = 0;
        }

        // Magic Cookie
        for(int idx = 0; idx < 4; idx++, i++){
            offer_b[i] = TramaDHCP.MAGIC_COOKIE[idx];
        }
        
        return offer_b;
    }

    public static byte[] crearACK(TramaDHCP request){
        return null;
    }

    public static byte[] crearNACK(TramaDHCP request){
        return null;
    }

    public void imprimirTramaDHCP(){
        String s = String.format("OP: %x", op);
        System.out.println(s);

        s = String.format("HTYPE: %x", htype);
        System.out.println(s);

        s = String.format("HLEN: %x", hlen);
        System.out.println(s);

        s = String.format("HOPS: %x", hops);
        System.out.println(s);

        s = "XID: ";
        for(int i=0; i < xid.length; i++){
            String s2 = String.format("%x ", xid[i]);
            s += s2;
        }
        System.out.println(s);

        s = "SECS: ";
        for(int i=0; i < secs.length; i++){
            String s2 = String.format("%x ", secs[i]);
            s += s2;
        }
        System.out.println(s);

        s = "FLAGS: ";
        for(int i=0; i < flags.length; i++){
            String s2 = String.format("%x ", flags[i]);
            s += s2;
        }
        System.out.println(s);

        s = "CIADDR: ";
        for(int i=0; i < ciaddr.length; i++){
            String s2 = String.format("%x ", ciaddr[i]);
            s += s2;
        }
        System.out.println(s);

        s = "YIADDR: ";
        for(int i=0; i < yiaddr.length; i++){
            String s2 = String.format("%x ", yiaddr[i]);
            s += s2;
        }
        System.out.println(s);

        s = "SIADDR: ";
        for(int i=0; i < siaddr.length; i++){
            String s2 = String.format("%x ", siaddr[i]);
            s += s2;
        }
        System.out.println(s);

        s = "GIADDR: ";
        for(int i=0; i < giaddr.length; i++){
            String s2 = String.format("%x ", giaddr[i]);
            s += s2;
        }
        System.out.println(s);

        s = "CHADDR: ";
        for(int i=0; i < chaddr.length; i++){
            String s2 = String.format("%x ", chaddr[i]);
            s += s2;
        }
        System.out.println(s);

        s = "SNAME: ";
        for(int i=0; i < sname.length; i++){
            String s2 = String.format("%x ", sname[i]);
            s += s2;
        }
        System.out.println(s);

        s = "FILE: ";
        for(int i=0; i < file.length; i++){
            String s2 = String.format("%x ", file[i]);
            s += s2;
        }
        System.out.println(s);

    }

    public byte getOp() {
        return this.op;
    }

    public void setOp(byte op) {
        this.op = op;
    }

    public byte getHtype() {
        return this.htype;
    }

    public void setHtype(byte htype) {
        this.htype = htype;
    }

    public byte getHlen() {
        return this.hlen;
    }

    public void setHlen(byte hlen) {
        this.hlen = hlen;
    }

    public byte getHops() {
        return this.hops;
    }

    public void setHops(byte hops) {
        this.hops = hops;
    }

    public byte[] getXid() {
        return this.xid;
    }

    public void setXid(byte[] xid) {
        this.xid = xid;
    }

    public byte[] getSecs() {
        return this.secs;
    }

    public void setSecs(byte[] secs) {
        this.secs = secs;
    }

    public byte[] getFlags() {
        return this.flags;
    }

    public void setFlags(byte[] flags) {
        this.flags = flags;
    }

    public byte[] getCiaddr() {
        return this.ciaddr;
    }

    public void setCiaddr(byte[] ciaddr) {
        this.ciaddr = ciaddr;
    }

    public byte[] getYiaddr() {
        return this.yiaddr;
    }

    public void setYiaddr(byte[] yiaddr) {
        this.yiaddr = yiaddr;
    }

    public byte[] getSiaddr() {
        return this.siaddr;
    }

    public void setSiaddr(byte[] siaddr) {
        this.siaddr = siaddr;
    }

    public byte[] getGiaddr() {
        return this.giaddr;
    }

    public void setGiaddr(byte[] giaddr) {
        this.giaddr = giaddr;
    }

    public byte[] getChaddr() {
        return this.chaddr;
    }

    public void setChaddr(byte[] chaddr) {
        this.chaddr = chaddr;
    }

    public byte[] getSname() {
        return this.sname;
    }

    public void setSname(byte[] sname) {
        this.sname = sname;
    }

    public byte[] getFile() {
        return this.file;
    }

    public void setFile(byte[] file) {
        this.file = file;
    }

}
