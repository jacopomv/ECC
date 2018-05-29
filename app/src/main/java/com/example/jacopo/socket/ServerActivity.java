package com.example.jacopo.socket;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.StrictMode;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.widget.TextView;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import de.frank_durr.ecdh_curve25519.ECDHCurve25519;

public class ServerActivity extends AppCompatActivity {

    public static final String TAG = ServerActivity.class.getSimpleName();
    private ServerSocket serverSocket;
    private Socket tempClientSocket;
    boolean createdKeys;
    Thread serverThread = null;
    public static final int SERVER_PORT = 3000;
    TextView messageTv;
    private String TAG_pub_server="pub_server";
    byte[] server_public_key;
    byte[] client_public_key;
    byte[] server_secret_key;
    byte[] server_shared_secret;
    private boolean hasReceivedKey=false;
    private IVGen IVGen =new IVGen();

    static {
        // Load native library ECDH-Curve25519-Mobile implementing Diffie-Hellman key
        // exchange with elliptic curve 25519.
        try {
            System.loadLibrary("ecdhcurve25519");
            Log.i(TAG, "Loaded ecdhcurve25519 library.");
        } catch (UnsatisfiedLinkError e) {
            Log.e(TAG, "Error loading ecdhcurve25519 library: " + e.getMessage());
        }
    }

    static {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }




    private void generateServerKeys() {

        if (!createdKeys) {
            // Create ClientActivity's secret key from a big random number.
            SecureRandom random = new SecureRandom();

            // Bob is also calculating a key pair.
            server_secret_key = ECDHCurve25519.generate_secret_key(random);
            server_public_key = ECDHCurve25519.generate_public_key(server_secret_key);
            SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
            SharedPreferences.Editor editor=sharedPref.edit();
            try {
                editor.putString(TAG_pub_server,new String(server_public_key,"UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            editor.commit();

        } else
            return;

    }
    private void generateShared(){
        //Generating Server shared key
        server_shared_secret = ECDHCurve25519.generate_shared_secret(
                server_secret_key, client_public_key);
        try {
            Log.i(TAG, "SHARED KEY: " + new String(server_shared_secret,"UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_server);

        messageTv = (TextView) findViewById(R.id.messageTv);
        Toolbar myToolbar = findViewById(R.id.my_toolbar);
        myToolbar.setTitle("Server");
        setSupportActionBar(myToolbar);

        String ip = ServerActivity.getIPAddress(true);
        System.out.println("IP ADD: "+ ip);

        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);

        generateServerKeys();
        this.serverThread = new Thread(new ServerRunnable());
        this.serverThread.start();

    }

    public void updateMessage(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                messageTv.append(message + "\n");
            }
        });
    }


    private void sendMessage(String message) {
        try {
            if (null != tempClientSocket) {
                PrintWriter out = new PrintWriter(new BufferedWriter(
                        new OutputStreamWriter(tempClientSocket.getOutputStream())),
                        true);
                out.println(message);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    class ServerRunnable implements Runnable {
        CommunicationThread commThread;

        public void run() {
            Socket socket;
            try {
                serverSocket = new ServerSocket(SERVER_PORT);
            } catch (IOException e) {
                e.printStackTrace();
            }
            if (null != serverSocket) {
                while (!Thread.currentThread().isInterrupted()) {
                    try {
                        socket = serverSocket.accept();
                        commThread = new CommunicationThread(socket);
                        DataOutputStream d = new DataOutputStream(socket.getOutputStream());
                        d.writeInt(server_public_key.length);
                        d.write(server_public_key);
                        d.writeInt(IVGen.getIv().length);
                        d.write(IVGen.getIv());
                        new Thread(commThread).start();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    class CommunicationThread implements Runnable {

        private Socket clientSocket;

        private DataInputStream input;

        public CommunicationThread(Socket clientSocket) {

            this.clientSocket = clientSocket;
            tempClientSocket = clientSocket;

            try {
                this.input = new DataInputStream(this.clientSocket.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }

            updateMessage("Server Started...");
            updateMessage("ClientActivity connected...");
        }

        public void run() {

            while (!Thread.currentThread().isInterrupted()) {

                try {


                    if(!hasReceivedKey){
                        int length = input.readInt();
                        if(length>0){
                            client_public_key = new byte[length];
                            input.readFully(client_public_key,0,client_public_key.length);
                        }

                        Log.i(TAG, "Message received from the client : " + client_public_key);
                        hasReceivedKey=true;

                        while(client_public_key==null) {

                        }
                        generateShared();

                    }else {

                        BufferedReader input_mex = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
                        String read = input_mex.readLine();
                        SecretKey originalKey = new SecretKeySpec(server_shared_secret, 0, server_shared_secret.length, "AES");
                        String mex=Util.decryptString(originalKey,read, IVGen.getIv());

                        Log.i(TAG, "Message Received from ClientActivity : " + mex);

                        if (null == read || "Disconnect".contentEquals(read)) {
                            Thread.interrupted();
                            read = "ClientActivity Disconnected";
                            updateMessage(getTime() + " | ClientActivity : " + read);
                            break;
                        }
                        updateMessage(getTime() + " | ClientActivity : " + "Message encrypted: "+read);
                        updateMessage(getTime() + " | ClientActivity : " + "Message decrypted: "+mex);
                    }

                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }

    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        if (null != serverThread) {
            sendMessage("Disconnect");
            serverThread.interrupt();
            serverThread = null;
        }

    }

    String getTime() {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        return sdf.format(new Date());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (null != serverThread) {
            sendMessage("Disconnect");
            serverThread.interrupt();
            serverThread = null;
        }
    }
    public static String getIPAddress(boolean useIPv4) {
        try {
            List<NetworkInterface> interfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface intf : interfaces) {
                List<InetAddress> addrs = Collections.list(intf.getInetAddresses());
                for (InetAddress addr : addrs) {
                    if (!addr.isLoopbackAddress()) {
                        String sAddr = addr.getHostAddress();
                        //boolean isIPv4 = InetAddressUtils.isIPv4Address(sAddr);
                        boolean isIPv4 = sAddr.indexOf(':')<0;

                        if (useIPv4) {
                            if (isIPv4)
                                return sAddr;
                        } else {
                            if (!isIPv4) {
                                int delim = sAddr.indexOf('%'); // drop ip6 zone suffix
                                return delim<0 ? sAddr.toUpperCase() : sAddr.substring(0, delim).toUpperCase();
                            }
                        }
                    }
                }
            }
        } catch (Exception ex) { } // for now eat exceptions
        return "";
    }
}