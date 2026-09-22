package org.picomatrix.bridge.embedded;

import android.app.Activity;
import android.content.Intent;
import android.database.ContentObserver;
import android.graphics.Color;
import android.net.Uri;
import android.os.*;
import android.view.WindowManager;
import android.widget.*;
import java.util.concurrent.*;

/** Restores login or shows the in-app sign-in before the original activity. */
public final class LaunchActivity extends Activity {
    private final ExecutorService work=Executors.newSingleThreadExecutor();
    private LinearLayout root;
    private TextView status;
    private Button retry,signIn;
    private AutoCloseable login;
    private boolean checking,launched,checkAgain;
    private final ContentObserver changed=new ContentObserver(new Handler(Looper.getMainLooper())) {
        @Override public void onChange(boolean self) { check(); }
    };
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(48,40,48,40);root.setBackgroundColor(Color.rgb(243,241,232));
        TextView title=new TextView(this);title.setText(getApplicationInfo().loadLabel(getPackageManager()));title.setTextSize(26);title.setTextColor(Color.rgb(25,27,24));root.addView(title);
        status=new TextView(this);status.setText("正在登录…");status.setTextSize(18);status.setPadding(0,24,0,24);root.addView(status);setContentView(root);
        retry=new Button(this);retry.setText("重试");retry.setVisibility(android.view.View.GONE);retry.setOnClickListener(v->check());root.addView(retry);
        signIn=new Button(this);signIn.setText("重新登录");signIn.setVisibility(android.view.View.GONE);signIn.setOnClickListener(v->showLogin());root.addView(signIn);
        getContentResolver().registerContentObserver(Uri.parse("content://"+getPackageName()+".matrix.provision"),false,changed);
        check();
    }
    @Override protected void onResume() { super.onResume();check(); }
    private void showLogin() {
        if(login!=null)return;
        try {login=EmbeddedRuntime.login(this,this::check);}
        catch(Exception e) {showRetry();}
    }
    private void showRetry() {
        if(login!=null) {try {login.close();}catch(Exception ignored) {}login=null;}
        setContentView(root);status.setText("暂时无法登录，请重试。");
        retry.setVisibility(android.view.View.VISIBLE);signIn.setVisibility(android.view.View.VISIBLE);
    }
    private void check() {
        if(launched || isDestroyed()) return;
        if(checking) {checkAgain=true;return;}checking=true;
        retry.setEnabled(false);signIn.setEnabled(false);status.setText("正在登录…");
        work.execute(()->{
            boolean ready=false,failed=false;String activity=null;
            try {ready=EmbeddedRuntime.ready(this);activity=EmbeddedRuntime.config(this).getString("launchActivity");}
            catch(Exception e) {failed=true;android.util.Log.w("MatrixBridge","embedded account startup: "+e.getClass().getSimpleName());}
            boolean available=ready,error=failed;String target=activity;
            runOnUiThread(()->{checking=false;if(isDestroyed() || launched)return;
                retry.setEnabled(true);signIn.setEnabled(true);
                if(available) {launched=true;startActivity(new Intent().setClassName(getPackageName(),target));finish();}
                else if(error) showRetry();
                else showLogin();
                if(checkAgain) {checkAgain=false;check();}
            });
        });
    }
    @Override protected void onDestroy() {
        getContentResolver().unregisterContentObserver(changed);work.shutdown();
        if(login!=null) try {login.close();}catch(Exception ignored) { }
        super.onDestroy();
    }
}
