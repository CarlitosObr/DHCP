/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;

/**
 *
 * @author carli
 */
public class ServidorDHCP implements Runnable {

    public final static int PORT = 67;
    public final static int CLIENT_PORT = 18000;
    public final static String DIR = "192.168.1.72";
    public final static DireccionIPv4 DIR_IPv4 = new DireccionIPv4("192:168:1:72");
    private final static String PATH = "C:\\Users\\carli\\Documents\\NetBeansProjects\\ACR20212\\src\\model";
    private DatagramSocket server;
    private DatagramPacket request;
    private byte[] inputBuffer;
    private static ArrayList<Subred> subredes;

    public ServidorDHCP(DatagramSocket server, DatagramPacket request, byte[] inputBuffer ){
        subredes = new ArrayList<>();
        this.server = server;
        this.request = request;
        this.inputBuffer = inputBuffer;
        configuracionInicial();
    }

    @Override
    public void run() {
        try{
            if(request.getLength() >= 236 && request.getLength() <= 300){ // Podria ser una trama DHCP
                        
                // Revisar las posiciones 44 a 47 que tienen el Magic Cookie
                boolean mensajeDHCP = true;
                for(int i=0; i < 4;i++){
                    if(TramaDHCP.MAGIC_COOKIE[i] != inputBuffer[236+i]){
                        mensajeDHCP = false;
                    }
                }

                if( mensajeDHCP ){
                    System.out.println("\nSe recibe un DHCP");
                    byte[] optionsData = DHCPOption.getSliceOfArray(inputBuffer, 240, request.getLength() );
                    ArrayList<DHCPOption> options = DHCPOption.getOptions(optionsData);
                    
                    for(DHCPOption o : options){
                        if( o.getCode() == 53 ){ // Tipo del mensaje DHCP
                            byte type = o.getBody()[0];
                            switch ( (int)(type & 0xFF) ){
                                case 1: // DISCOVER
                                    System.out.println("Mensaje DISCOVER");
                                    byte[] offer = crearOffer(inputBuffer,options);
                                    if(offer != null){
                                        DatagramPacket response = new DatagramPacket(offer, offer.length, InetAddress.getByName("255.255.255.255"), 
                                                                                ServidorDHCP.CLIENT_PORT);
                                        server.send(response);
                                    }
                                    break;

                                case 3: // <REQUEST>
                                    System.out.println("Mensaje REQUEST");
                                    byte[] ACK = crearACK(inputBuffer,options);
                                    if(ACK != null){
                                        DatagramPacket response = new DatagramPacket(ACK, ACK.length, InetAddress.getByName("255.255.255.255"), 
                                                                                ServidorDHCP.CLIENT_PORT);
                                        server.send(response);
                                    }else{
                                        byte[] NACK = crearNACK(inputBuffer,options);
                                        DatagramPacket response = new DatagramPacket(NACK, NACK.length, InetAddress.getByName("255.255.255.255"), 
                                                                                ServidorDHCP.CLIENT_PORT);
                                        server.send(response);
                                    }
                                    break;

                                case 7: // RELEASE
                                    System.out.println("Mensaje RELEASE");
                                    liberarIP(inputBuffer);
                                    break;

                                default:
                                    break;
                            }
                        }
                    }
                }
            }
        } catch (SocketException e1) {
            e1.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
        } catch( ArrayIndexOutOfBoundsException e){
            e.printStackTrace();
        }
        finally{
            //server.close();
        }
    }
    
    private static byte[] crearOffer(byte[] encabezadoDHCP, ArrayList<DHCPOption> opciones){
        TramaDHCP tramaDHCP = TramaDHCP.crearTramaDHCP(encabezadoDHCP);
        //tramaDHCP.imprimirTramaDHCP();
        // A la trama DISCOVER hay que hacerle los siguiente cambios para convertirla en una OFFER
        // 1. Cambiar el OP al correspondiente
        tramaDHCP.setOp(new Integer(2).byteValue());
        // 2. Buscar si el cliente solicita una dirección IP
        DireccionIPv4 direccionSolicitada = null;
        for(DHCPOption opcion : opciones){
            if(opcion.getCode() == 50){
                direccionSolicitada = new DireccionIPv4(opcion.getBody());
            }
        }
        // 3. Asignar una direccion IP.
        direccionSolicitada = buscarDireccion(direccionSolicitada);
    
        if(direccionSolicitada == null){
            return null;
        }
        
        // 3.1 Encontrar la subred donde se encuentra esta dirección IP
        Subred subred = buscarSubred(direccionSolicitada);
        
        // 3.2 Mensaje Broadcast
        byte[] bootFlags = new byte[2];
        bootFlags[0] = Integer.valueOf(0x80).byteValue();
        bootFlags[1] = Integer.valueOf(0).byteValue();
        tramaDHCP.setFlags(bootFlags);
        
        // 4. Asignar YIADDR
        tramaDHCP.setYiaddr(direccionSolicitada.getDireccion());

        // 5. Asignar SIADDR
        tramaDHCP.setSiaddr(ServidorDHCP.DIR_IPv4.getDireccion());

        // 6. Crear una lista con las opcion
        ArrayList<DHCPOption> opcionesOffer = DHCPOption.armarOfferOptions(subred.getMascara(), subred.getGateway(),
                                                                            subred.getTiemposArrendamiento().get(direccionSolicitada), 
                                                                            ServidorDHCP.DIR_IPv4, subred.getDns());

        // 7. Crear un arrgle de byte con las opciones
        byte[] opccionesOffer_b = DHCPOption.opcionesAbytes(opcionesOffer);

        // 8. Crear el arreglo que se debe retornar
        byte[] offer = new byte[240 + opccionesOffer_b.length]; // 236(Encabezado) + 4(Cookie) + opciones.lenght  
        
        // 9. Llenar el encabezado
        byte[] encabezado = TramaDHCP.crearOffer(tramaDHCP);
        for(int i=0; i < 240; i++){
            offer[i] = encabezado[i];
        }

        // 10. Poner las opciones
        int idx = 240;
        for(int i=0; i < opccionesOffer_b.length; i++, idx++){
            offer[idx] = opccionesOffer_b[i];
        }
        return offer;
    }

    private static byte[] crearACK(byte[] encabezadoDHCP, ArrayList<DHCPOption> opciones){
        TramaDHCP tramaDHCP = TramaDHCP.crearTramaDHCP(encabezadoDHCP);
        //tramaDHCP.imprimirTramaDHCP();

        // A la trama REQUEST hay que hacerle los siguiente cambios para convertirla en una ACK
        // 1. Cambiar el OP al correspondiente
        tramaDHCP.setOp(new Integer(2).byteValue());

        // 2. Buscar la dirección IP que solicita el cliente
        DireccionIPv4 direccionSolicitada = null;
        for(DHCPOption opcion : opciones){
            if(opcion.getCode() == 50){
                direccionSolicitada = new DireccionIPv4(opcion.getBody());
            }
        }

        // 3. Asignar una direccion IP.
        DireccionIPv4 dir = buscarDireccion(direccionSolicitada);
        if(!dir.equals(direccionSolicitada)){
            System.out.println("Dirección ocupada o ilegitima");
            return null;
        }
        
        // 3.1 Encontrar la subred donde se encuentra esta dirección IP
        Subred subred = buscarSubred(direccionSolicitada);

        ocuparIP(direccionSolicitada); // Ocupar la IP ya que se va a asignar
        
        // 4. Asignar YIADDR
        tramaDHCP.setYiaddr(direccionSolicitada.getDireccion());

        // 5. Asignar SIADDR
        tramaDHCP.setSiaddr(ServidorDHCP.DIR_IPv4.getDireccion());

        /*System.out.println(direccionSolicitada.hashCode() + " :: " + direccionSolicitada.toString());
        for(DireccionIPv4 d : subred.getTiemposArrendamiento().keySet()){
            System.out.println(d.hashCode() + ": " + d.toString());
        }*/
        // 6. Crear una lista con las opciones
        ArrayList<DHCPOption> opcionesOffer = DHCPOption.armarACKOptions(subred.getMascara(), subred.getGateway(),
                                                                            subred.getTiemposArrendamiento().get(direccionSolicitada), 
                                                                            ServidorDHCP.DIR_IPv4, subred.getDns());   

        // 7. Crear un arrgle de byte con las opciones
        byte[] opccionesOffer_b = DHCPOption.opcionesAbytes(opcionesOffer);

        // 8. Crear el arreglo que se debe retornar
        byte[] offer = new byte[240 + opccionesOffer_b.length]; // 236(Encabezado) + 4(Cookie) + opciones.lenght  
        
        // 9. Llenar el encabezado
        byte[] encabezado = TramaDHCP.crearOffer(tramaDHCP);
        for(int i=0; i < 240; i++){
            offer[i] = encabezado[i];
        }

        // 10. Poner las opciones
        int idx = 240;
        for(int i=0; i < opccionesOffer_b.length; i++, idx++){
            offer[idx] = opccionesOffer_b[i];
        }

        // 11. Escribir el registro en log.txt
        try {
            int[] mac = new int[6];
            for(int i=0; i < 6; i++){
                mac[i] = tramaDHCP.getChaddr()[i] & 0xFF;
            }
            String mac_s = String.format("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            
            int[] ip = new int[4];
            for(int i=0; i < 4; i++){
                ip[i] = tramaDHCP.getYiaddr()[i] & 0xFF;
            }
            String ip_s = String.format("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
            
            DateFormat dateFormat = new SimpleDateFormat("HH:mm:ss");
            Date date = new Date();
            
            FileWriter fileWriter = new FileWriter(PATH + "log.txt",true);
            String registro;
            registro = mac_s + "," + ip_s + "," + dateFormat.format(date) + "," + dateFormat.format(date) + "\n";
            fileWriter.write(registro);
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return offer;
    }

    private static byte[] crearNACK(byte[] encabezadoDHCP, ArrayList<DHCPOption> opciones){
        TramaDHCP tramaDHCP = TramaDHCP.crearTramaDHCP(encabezadoDHCP);
        // A la trama DISCOVER hay que hacerle los siguiente cambios para convertirla en una OFFER
        // 1. Cambiar el OP al correspondiente
        tramaDHCP.setOp(new Integer(2).byteValue());

        // 2. Mensaje Broadcast
        byte[] bootFlags = new byte[2];
        bootFlags[0] = Integer.valueOf(0x80).byteValue();
        bootFlags[1] = Integer.valueOf(0).byteValue();
        tramaDHCP.setFlags(bootFlags);
        
        // 3. Todo a 0 menos el servidor
        tramaDHCP.setSiaddr(ServidorDHCP.DIR_IPv4.getDireccion());

        // 6. Crear una lista con las opcion
        ArrayList<DHCPOption> opcionesOffer = DHCPOption.armarNACKOptions();

        // 7. Crear un arrgle de byte con las opciones
        byte[] opccionesOffer_b = DHCPOption.opcionesAbytes(opcionesOffer);

        // 8. Crear el arreglo que se debe retornar
        byte[] offer = new byte[240 + opccionesOffer_b.length]; // 236(Encabezado) + 4(Cookie) + opciones.lenght  
        
        // 9. Llenar el encabezado
        byte[] encabezado = TramaDHCP.crearOffer(tramaDHCP);
        for(int i=0; i < 240; i++){
            offer[i] = encabezado[i];
        }

        // 10. Poner las opciones
        int idx = 240;
        for(int i=0; i < opccionesOffer_b.length; i++, idx++){
            offer[idx] = opccionesOffer_b[i];
        }
        return offer;
    }

    private static void liberarIP(byte[] encabezadoDHCP){
        TramaDHCP tramaDHCP = TramaDHCP.crearTramaDHCP(encabezadoDHCP);
        DireccionIPv4 dirLiberar = new DireccionIPv4(tramaDHCP.getCiaddr());
        System.out.println("Se libera: " + dirLiberar.toString()); 
        ArrayList<Subred> sbr = new ArrayList<>();
        for(Subred s : subredes){
            ArrayList<DireccionIPv4>dirs = new ArrayList<>();
            for(DireccionIPv4 dir : s.getDirecciones()){
                DireccionIPv4 temp = dir;
                if(dir.equals(dirLiberar)){  
                    temp = new DireccionIPv4(dir.getDireccion()); 
                }
                dirs.add(temp);
            }
            Subred s2 = new Subred(dirs, s.getMascara(), s.getGateway(), s.getDns());
            s2.setTiemposArrendamiento(s.getTiemposArrendamiento());
            sbr.add(s2);
        }
        subredes.clear();
        for(Subred s : sbr){
            ArrayList<DireccionIPv4>dirs = new ArrayList<>();
            for(DireccionIPv4 dir : s.getDirecciones()){
                dirs.add(new DireccionIPv4(dir.getDireccion(),dir.getLibre()));
            }
            Subred s2 = new Subred(dirs, s.getMascara(), s.getGateway(), s.getDns());
            s2.setTiemposArrendamiento(s.getTiemposArrendamiento());
            subredes.add(s2);
        }
    }

    private static void ocuparIP(DireccionIPv4 dirOcupar){
        ArrayList<Subred> sbr = new ArrayList<>();
        for(Subred s : subredes){
            ArrayList<DireccionIPv4>dirs = new ArrayList<>();
            for(DireccionIPv4 dir : s.getDirecciones()){
                DireccionIPv4 temp = dir;
                if(dir.equals(dirOcupar)){
                    System.out.println("Se ocupa: " + dir.toString());     
                    temp = new DireccionIPv4(dir.getDireccion(),false);; 
                }
                dirs.add(temp);
            }
            Subred s2 = new Subred(dirs, s.getMascara(), s.getGateway(), s.getDns());
            s2.setTiemposArrendamiento(s.getTiemposArrendamiento());
            sbr.add(s2);
        }
        subredes.clear();
        for(Subred s : sbr){
            ArrayList<DireccionIPv4>dirs = new ArrayList<>();
            for(DireccionIPv4 dir : s.getDirecciones()){
                dirs.add(new DireccionIPv4(dir.getDireccion(),dir.getLibre()));
            }
            Subred s2 = new Subred(dirs, s.getMascara(), s.getGateway(), s.getDns());
            s2.setTiemposArrendamiento(s.getTiemposArrendamiento());
            subredes.add(s2);
        }
    }
    
    private static DireccionIPv4 buscarDireccion(DireccionIPv4 direccion){
        
        if(direccion != null){
            for(Subred subred : subredes){
                for(DireccionIPv4 dir : subred.getDirecciones()){
                    if(dir.equals(direccion) && dir.getLibre()){
                        return dir;
                    }
                }
            }
        }
        // Buscar una dirección disponible en las subredes creadas
        for(Subred subred : subredes){
            for(DireccionIPv4 dir : subred.getDirecciones()){
                if(dir.getLibre()){
                    return dir;
                }
            }
        }
        System.out.println("No hay direcciones libres");

        return null; 
    }

    private static Subred buscarSubred(DireccionIPv4 direccion){
        Subred subred = null;
        for(Subred s : subredes){
            for(DireccionIPv4 dir : s.getDirecciones()){
                if(dir.equals(direccion)){
                    subred = s;
                }
            }
        }
        return subred;
    }

    public void configuracionInicial(){
        try {
            File configuracion = new File(PATH + "configuracion.txt");
            Scanner myReader = new Scanner(configuracion);
            boolean readStats = true;
            int direcciones = 0;
            int idx = 0;
            Subred subred = null;
            HashMap<DireccionIPv4,Integer> tiemposArrendamiento = null;

            while (myReader.hasNextLine()) {
              String line = myReader.nextLine();
              if(readStats){
                String[] parameters = line.split(";");
                subred = construirSubred(parameters);
                direcciones = Integer.parseInt(parameters[1]);
                idx = 0;
                tiemposArrendamiento = new HashMap<DireccionIPv4,Integer>();
                readStats = false;
              }else{
                if(idx < direcciones){
                    tiemposArrendamiento.put(subred.getDirecciones().get(idx), Integer.valueOf(line));
                    idx++;
                    if(idx == direcciones){
                        subred.setTiemposArrendamiento(tiemposArrendamiento);
                        subredes.add(subred);
                        subred = null;
                        tiemposArrendamiento = null;
                        readStats = true;
                    }
                }
              }
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("No se encuentra configuracion.txt!");
            e.printStackTrace();
        }
    }

    private Subred construirSubred(String[] parameters){
        Subred subred;
        String[] inicial_final = parameters[0].split(",");
        int totalDirecciones = Integer.parseInt(parameters[1]);
        ArrayList<DireccionIPv4> direcciones = new ArrayList<DireccionIPv4>();

        int[] direccion = new DireccionIPv4(inicial_final[0]).direccionEnteros();
        int direccionInicial = direccion[3];
        for(int i=0; i < totalDirecciones; i++){
            direccion[3] = direccionInicial + i;
            direcciones.add(new DireccionIPv4(direccion));
        }
        DireccionIPv4 mascara = new DireccionIPv4(parameters[2]);
        DireccionIPv4 gateway = new DireccionIPv4(parameters[3]);
        DireccionIPv4 dns = new DireccionIPv4(parameters[4]);
        
        subred = new Subred(direcciones, mascara, gateway, dns);
        
        return subred;
    }

    public void imprimirRedes(){
        int cont = 1;

        for(Subred subred : subredes){
            System.out.println("SUBRED " + String.valueOf(cont));
            System.out.println("Direcciones:");
            for(DireccionIPv4 dir : subred.getDirecciones()){
                System.out.println("\t" + dir.toString());
            }
            System.out.println("MASCARA: " + subred.getMascara().toString());
            System.out.println("GATEWAY: " + subred.getGateway().toString());
            System.out.println("DNS: " + subred.getDns().toString());
            System.out.println("Tiempos de arrendamiento:");
            for(DireccionIPv4 key : subred.getTiemposArrendamiento().keySet()){
                System.out.println("\t" + subred.getTiemposArrendamiento().get(key));
            }
            System.out.println("==================================");
            cont++;
        }
    }

    public static void main(String[] args){
        DatagramSocket server = null;
        try {
            server = new DatagramSocket(ServidorDHCP.PORT,InetAddress.getByName(ServidorDHCP.DIR));   
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        while (true) {
            DatagramPacket request = null;
            byte[] inputBuffer = null;
            try{
                
                inputBuffer = new byte[512];
                request = new DatagramPacket(inputBuffer, inputBuffer.length);
                server.receive(request);
                if(request.getPort() == CLIENT_PORT){
                    new Thread(new ServidorDHCP(server, request, inputBuffer)).start();
                }
                
            } catch (Exception e) {
                e.printStackTrace();
            } 
        }
    }
}
