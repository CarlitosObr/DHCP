/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package model;

import java.util.ArrayList;
import java.util.HashMap;

/**
 *
 * @author carli
 */
public class Subred {
    
    private ArrayList<DireccionIPv4> direcciones;
    private DireccionIPv4 mascara;
    private DireccionIPv4 gateway;
    private DireccionIPv4 dns;
    private HashMap<DireccionIPv4,Integer> tiemposArrendamiento;

    public Subred(ArrayList<DireccionIPv4> direcciones, DireccionIPv4 mascara, DireccionIPv4 gateway, DireccionIPv4 dns) {
        this.direcciones = direcciones;
        this.mascara = mascara;
        this.gateway = gateway;
        this.dns = dns;
    }


    public ArrayList<DireccionIPv4> getDirecciones() {
        return this.direcciones;
    }

    public void setDirecciones(ArrayList<DireccionIPv4> direcciones) {
        this.direcciones = direcciones;
    }

    public DireccionIPv4 getMascara() {
        return this.mascara;
    }

    public void setMascara(DireccionIPv4 mascara) {
        this.mascara = mascara;
    }

    public DireccionIPv4 getGateway() {
        return this.gateway;
    }

    public void setGateway(DireccionIPv4 gateway) {
        this.gateway = gateway;
    }

    public DireccionIPv4 getDns() {
        return this.dns;
    }

    public void setDns(DireccionIPv4 dns) {
        this.dns = dns;
    }

    public HashMap<DireccionIPv4,Integer> getTiemposArrendamiento() {
        return this.tiemposArrendamiento;
    }

    public void setTiemposArrendamiento(HashMap<DireccionIPv4,Integer> tiemposArrendamiento) {
        this.tiemposArrendamiento = tiemposArrendamiento;
    }

}
