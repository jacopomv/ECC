package com.example.jacopo.socket;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.os.StrictMode;
import android.preference.PreferenceManager;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import de.frank_durr.ecdh_curve25519.ECDHCurve25519;

public class ClientActivity extends AppCompatActivity implements View.OnClickListener {

    public static final String PREFS_NAME = "MyPrefsFile";
    public static final String TAG = ClientActivity.class.getSimpleName();

    //Encryption variables
    boolean createdKeys;
    //String plainText = "";
    private EditText msg;
    private byte[] client_secret_key;
    private byte[] client_public_key;
    private byte[] client_shared_secret;
    volatile byte[] server_public_key;

    public static final int SERVERPORT = 3000;

    public static final String SERVER_IP = "192.168.43.71";
    ClientThread clientRunnable;
    Thread thread;
    TextView messageTv;
    private final String TAG_pub_client="pub_client";
    private boolean hasReceivedKey=false;
    byte [] firstKeyName;
    byte [] iv;


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



    private void generateClientKeys() {

        if (!createdKeys) {
            // Create ClientActivity's secret key from a big random number.
            SecureRandom random = new SecureRandom();
            client_secret_key = ECDHCurve25519.generate_secret_key(random);
            // Create ClientActivity's public key.
            client_public_key = ECDHCurve25519.generate_public_key(client_secret_key);

            SharedPreferences sharedPref = PreferenceManager.getDefaultSharedPreferences(getApplicationContext());
            SharedPreferences.Editor editor=sharedPref.edit();
            try {
                editor.putString(TAG_pub_client,new String(client_public_key,"UTF-8"));
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            editor.commit();
        } else
            return;

    }

    public void generateShared(){
        //System.out.println("LUNGHEZZA:  "+server_public_key.length + "CLIENT" + client_secret_key.length);
        client_shared_secret = ECDHCurve25519.generate_shared_secret(
                client_secret_key, server_public_key);
        try {
            Log.i(TAG, "SHARED KEY: " + new String(client_shared_secret,"UTF-8"));
                    } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_client);
        messageTv = (TextView) findViewById(R.id.messageTv);

        Toolbar myToolbar = findViewById(R.id.my_toolbar);
        myToolbar.setTitle("ECC Message Exchange - ClientActivity");
        setSupportActionBar(myToolbar);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        generateClientKeys();

        clientRunnable = new ClientThread();
        thread = new Thread(clientRunnable);
        thread.start();

        //Intent myIntent = getIntent(); // gets the previously created intent
        //firstKeyName = myIntent.getByteArrayExtra("iv");
        //byte[] iv = new SecureRandom().generateSeed(32);
        //test=new Test(firstKeyName);



        msg = (EditText) findViewById(R.id.message);

        SharedPreferences settings = getSharedPreferences(PREFS_NAME, 0);
        SharedPreferences.Editor editor = settings.edit();
        editor.putBoolean("createdKeys", false);

        editor.commit();
    }

    public void updateMessage(final String message) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                messageTv.append(message + "\n");
            }
        });
    }

    @Override
    public void onClick(View view) {

        /*if (view.getId() == R.id.connect_server) {
            messageTv.setText("");
            return;
        }*/

        if (view.getId() == R.id.send_data) {
            SecretKey originalKey = new SecretKeySpec(client_shared_secret, 0, client_shared_secret.length, "AES");

            String encrypted=Util.encryptString(originalKey,msg.getText().toString(),iv);
            //Log.i(TAG, "IV : " + test.iv);

            Log.i(TAG, "Message encrypted : " + encrypted);
            clientRunnable.sendMessage(encrypted);
        }
    }

    class ClientThread implements Runnable {

        private Socket socket;
        private DataInputStream input;

        @Override
        public void run() {

            try {
                //System.out.println("IN RUN");
                InetAddress serverAddr = InetAddress.getByName(SERVER_IP);
                socket = new Socket(serverAddr, SERVERPORT);
                if(!hasReceivedKey){
                    DataOutputStream d = new DataOutputStream(socket.getOutputStream());
                    d.writeInt(client_public_key.length);
                    d.write(client_public_key);
                } else {
                    PrintWriter out = new PrintWriter(new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream())),
                    true);
                    out.println();
                    out.println(client_public_key+"");

                }

                while (!Thread.currentThread().isInterrupted()) {

                    Log.i(TAG, "Waiting for message from server...");

                    this.input = new DataInputStream(socket.getInputStream());

                    if(!hasReceivedKey){
                        int length = input.readInt();
                        if(length>0) {
                            server_public_key = new byte[length];
                            input.readFully(server_public_key, 0, server_public_key.length);
                            int iv_lenght=input.readInt();
                            iv=new byte[iv_lenght];
                            input.readFully(iv,0,iv_lenght);
                            while (server_public_key == null) {
                                Thread.sleep(1000);
                            }
                        }
                        //System.out.println("FUORI DAL WHILE:"+ server_public_key);
                        generateShared();
                        //System.out.println("LEONISIOOOO_CLIENT");

                    } else {
                        BufferedReader input_mex = new BufferedReader(new InputStreamReader(this.socket.getInputStream()));
                        String message = input_mex.readLine();
                        //String mex=test.decryptString(secretKeyA,read);
                        Log.i(TAG, "Message Received from ClientActivity : " + message);


                        Log.i(TAG, "Message received from the server : " + message);

                        if (null == message || "Disconnect".contentEquals(message)) {
                            Thread.interrupted();
                            message = "Server Disconnected.";
                            updateMessage(getTime() + " | Server : " + message);
                            break;
                        }

                        updateMessage(getTime() + " | Server : " + message);

                    }
                }

            } catch (ConnectException conn) {
                Toast.makeText(ClientActivity.this, "Impossible to connect to server", Toast.LENGTH_SHORT).show();

            }
            catch (Exception e1) {
                e1.printStackTrace();
            }
        }

        void sendMessage(String message) {
            try {
                if (null != socket) {
                    PrintWriter out = new PrintWriter(new BufferedWriter(
                            new OutputStreamWriter(socket.getOutputStream())),
                            true);
                    out.println(message);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }


        }

    }

    String getTime() {
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        return sdf.format(new Date());
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (null != clientRunnable) {
            clientRunnable.sendMessage("Disconnect");
            clientRunnable = null;
        }
    }

}