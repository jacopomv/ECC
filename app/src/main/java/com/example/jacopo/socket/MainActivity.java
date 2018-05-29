package com.example.jacopo.socket;

import android.content.Intent;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;

public class MainActivity extends AppCompatActivity implements View.OnClickListener{

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Toolbar myToolbar = (Toolbar) findViewById(R.id.my_toolbar);
        myToolbar.setTitle("ECC Message Exchange");
        setSupportActionBar(myToolbar);

    }
    @Override
    public void onClick(View view) {
        if (view.getId() == R.id.switchToServer) {
            Intent intent=new Intent(MainActivity.this,ServerActivity.class);
            MainActivity.this.startActivity(intent);

        }
        if(view.getId() == R.id.switchToC){
            Intent intent=new Intent(MainActivity.this,ClientActivity.class);
            MainActivity.this.startActivity(intent);
        }
    }

}
