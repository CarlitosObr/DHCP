/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import java.nio.ByteBuffer;
import java.util.ArrayList;

/**
 *
 * @author carli
 */
public class DHCPOption { // Opciones definidas en el RFC 1533
 
    private int code;
    private int len;
    private byte[] body;

    public DHCPOption(byte code, byte len, byte[] body){
        this.code = code & 0xFF;
        this.len = len & 0xFF;
        this.body = new byte[this.len];
        for(int i=0; i < this.len; i++){
            this.body[i] = body[i];
        }  
    }

    public static ArrayList<DHCPOption> getOptions(byte[] data){

        ArrayList<DHCPOption> options = new ArrayList<>();
        int pos = 0;

        while( data[pos] != new Integer(0xFF).byteValue() ){ // Endmark : 255
            
            DHCPOption option = new DHCPOption( data[pos], data[pos + 1], getSliceOfArray(data,pos+2,data.length));
            pos += 2 + option.len;
            options.add(option);
        }
        return options;
    }

    public static byte[] getSliceOfArray(byte[] arr, int start, int end) 
    { 
        // Get the slice of the Array 
        byte[] slice = new byte[end - start]; 
  
        // Copy elements of arr to slice 
        for (int i = 0; i < slice.length; i++) { 
            slice[i] = arr[start + i]; 
        } 
  
        // return the slice 
        return slice; 
    } 

    public static ArrayList<DHCPOption> armarOfferOptions(DireccionIPv4 mascara, DireccionIPv4 giaddr, int tiempoArrendamiento,
                                            DireccionIPv4 servidor, DireccionIPv4 dns) {
        
        ArrayList<DHCPOption> opciones = new ArrayList<>();
        
        // 1. Offer
        byte [] body = new byte[1];
        body[0] = new Integer(2).byteValue();
        DHCPOption opcion = new DHCPOption(new Integer(53).byteValue(), new Integer(1).byteValue(), body);
        opciones.add(opcion);

        // 2. Mascara de subred
        opcion = new DHCPOption(new Integer(1).byteValue(), new Integer(4).byteValue(), mascara.getDireccion());
        opciones.add(opcion);

        // 3. Router
        opcion = new DHCPOption(new Integer(3).byteValue(), new Integer(4).byteValue(), giaddr.getDireccion());
        opciones.add(opcion);

        // 4. Tiempo arrendamiento
        opcion = new DHCPOption(new Integer(51).byteValue(), new Integer(4).byteValue(), 
                                ByteBuffer.allocate(4).putInt(tiempoArrendamiento).array());
        opciones.add(opcion);

        // 5. Server identifier
        opcion = new DHCPOption(new Integer(54).byteValue(), new Integer(4).byteValue(), servidor.getDireccion());
        opciones.add(opcion);
        
        // 6. DNS
        opcion = new DHCPOption(new Integer(6).byteValue(), new Integer(4).byteValue(), dns.getDireccion());
        opciones.add(opcion);

        return opciones;
    }

    public static ArrayList<DHCPOption> armarACKOptions(DireccionIPv4 mascara, DireccionIPv4 giaddr, int tiempoArrendamiento,
                                            DireccionIPv4 servidor, DireccionIPv4 dns) {
        
        ArrayList<DHCPOption> opciones = new ArrayList<>();
        
        // 1. ACK
        byte [] body = new byte[1];
        body[0] = new Integer(5).byteValue();
        DHCPOption opcion = new DHCPOption(new Integer(53).byteValue(), new Integer(1).byteValue(), body);
        opciones.add(opcion);

        // 2. Mascara de subred
        opcion = new DHCPOption(new Integer(1).byteValue(), new Integer(4).byteValue(), mascara.getDireccion());
        opciones.add(opcion);

        // 3. Router
        opcion = new DHCPOption(new Integer(3).byteValue(), new Integer(4).byteValue(), giaddr.getDireccion());
        opciones.add(opcion);

        // 4. Tiempo arrendamiento
        opcion = new DHCPOption(new Integer(51).byteValue(), new Integer(4).byteValue(), 
                                ByteBuffer.allocate(4).putInt(tiempoArrendamiento).array());
        opciones.add(opcion);

        // 5. Server identifier
        opcion = new DHCPOption(new Integer(54).byteValue(), new Integer(4).byteValue(), servidor.getDireccion());
        opciones.add(opcion);

        return opciones;
    }

    public static ArrayList<DHCPOption> armarRequestOptions() {
        
        ArrayList<DHCPOption> opciones = new ArrayList<>();
        
        // 1. ACK
        byte [] body = new byte[1];
        body[0] = new Integer(3).byteValue();
        DHCPOption opcion = new DHCPOption(new Integer(53).byteValue(), new Integer(1).byteValue(), body);
        opciones.add(opcion);

        // 2. Mascara de subred
        opcion = new DHCPOption(new Integer(50).byteValue(), new Integer(4).byteValue(), new DireccionIPv4("192:168:0:201").getDireccion());
        opciones.add(opcion);

        opcion = new DHCPOption(new Integer(54).byteValue(), new Integer(4).byteValue(), new DireccionIPv4("192:168:0:25").getDireccion());
        opciones.add(opcion);

        return opciones;
    }

    public static ArrayList<DHCPOption> armarNACKOptions() {
        
        ArrayList<DHCPOption> opciones = new ArrayList<>();
        
        // 1. NACK
        byte [] body = new byte[1];
        body[0] = new Integer(6).byteValue();
        DHCPOption opcion = new DHCPOption(new Integer(53).byteValue(), new Integer(1).byteValue(), body);
        opciones.add(opcion);

        return opciones;
    }

    public static byte[] opcionesAbytes(ArrayList<DHCPOption> opciones){
        byte[] ops = null;
        int longitud = 0;
        for(DHCPOption o : opciones){
            longitud += 2 + o.getLen(); // Codigo + longitud + cuerpo 
        }
        longitud += 1; // Cierre
        ops = new byte[longitud];
        int idx = 0;
        for(DHCPOption o : opciones){
            ops[idx++] = Integer.valueOf(o.getCode()).byteValue();
            ops[idx++] = Integer.valueOf(o.getLen()).byteValue();
            for(int i=0; i < o.getLen(); i++,idx++){
                ops[idx] = o.getBody()[i];
            }
        }
        ops[idx] = Integer.valueOf(0xFF).byteValue(); // CIERRE (255)
        return ops;
    }

    public void printBody(){
        for(int i=0; i < this.len; i++){
            String s = String.format("%x ", body[i]);
            System.out.print(s);
            if(i%5 == 0){
                System.out.println("");
            }
        }
    }

    public int getCode() {
        return this.code;
    }

    public int getLen() {
        return this.len;
    }

    public byte[] getBody() {
        return this.body;
    }

}
