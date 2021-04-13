/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;

/**
 *
 * @author carli
 */
public class Cliente {

    public final static int PORT = 19000;

    public Cliente() {

        try {
            DatagramSocket client = new DatagramSocket(Cliente.PORT);
            
            byte[] rqst = crearRequest();

            DatagramPacket request = new DatagramPacket(rqst, rqst.length, 
                                                        InetAddress.getByName("255.255.255.255"), ServidorDHCP.PORT);
            client.send(request);
            client.close();
        } catch (SocketException e) {
            e.printStackTrace();
        } catch (UnknownHostException e){
            e.printStackTrace();
        } catch (IOException e){
            e.printStackTrace();
        }

    }

    private static byte[] crearRequest(){
        
        byte[] encabezado = TramaDHCP.crearRequest();

        // 6. Crear una lista con las opcion
        ArrayList<DHCPOption> opcionesOffer = DHCPOption.armarRequestOptions();

        // 7. Crear un arrgle de byte con las opciones
        byte[] opccionesOffer_b = DHCPOption.opcionesAbytes(opcionesOffer);

        // 8. Crear el arreglo que se debe retornar
        byte[] offer = new byte[240 + opccionesOffer_b.length]; // 236(Encabezado) + 4(Cookie) + opciones.lenght  
        
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


    public static void main(String[] args) throws InterruptedException{
        new Cliente();
    }
}
