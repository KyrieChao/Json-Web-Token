package com.chao.key_minter_Test.demo;

import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.Session;

import java.io.InputStream;
import java.util.UUID;

public class RemoteExecDemo {

    public static void main(String[] args) throws Exception {

        String host = "192.168.88.132";
        String user = "chao";
        String password = "893760";
        int port = 22;
        JSch jsch = new JSch();
        Session session = jsch.getSession(user, host, port);
        session.setPassword(password);
        JSch.setConfig("StrictHostKeyChecking", "yes");
        jsch.setKnownHosts(System.getProperty("user.home") + "/.ssh/known_hosts");
        session.connect(5000);
        String id = UUID.randomUUID().toString().replaceAll("-", "").substring(0, 8);
        String code = String.format("""
                import java.util.Scanner;
                public class %s  {
                    public static void main(String[] args) {
                        Scanner sc = new Scanner(System.in);
                        int a = sc.nextInt();
                        int b = sc.nextInt();
                        System.out.println(a + b);
                    }
                }
                """, id);
        String cmd2 = String.format("""
                parallel -k -j 4 '
                  echo "====================="
                  nsjail -Mo -Q \\
                    --disable_clone_newuser   --disable_clone_newpid \\
                    --disable_clone_newnet    --disable_clone_newipc \\
                    --disable_clone_newuts    --disable_clone_newns \\
                    --disable_clone_newcgroup \\
                    --cwd '"$(pwd)"' \\
                    --time_limit 3 --rlimit_cpu 2 --rlimit_as 524288 --rlimit_nofile 1024 \\
                    -- /usr/bin/time -f "args={}\\nelapsed=%%E\\nuser=%%U\\nsys=%%S\\nmaxrss_kb=%%M\\nexit=%%x" \\
                      /usr/bin/java -cp . %s <<< {} 2>&1
                ' ::: "7 8" "4 10" "-1 10" "0 -15" "3 5"
                """, id);
        // === 1. 先编译 ===
        ChannelExec ch1 = (ChannelExec) session.openChannel("exec");
        String compile = String.format(
                "cd /home/chao/work/test/java && echo '%s' > %s.java && javac %s.java 2>&1 && echo ok || echo err",
                code.replace("'", "'\\''"), id, id);
        ch1.setCommand(compile);
        ch1.connect();
        // 等编译结果
        StringBuilder res = new StringBuilder();
        try (InputStream in = ch1.getInputStream()) {
            for (int c; (c = in.read()) != -1; ) res.append((char) c);
        }
        ch1.disconnect();
        System.out.print(res);
        if (!res.toString().trim().equals("ok")) {
            System.out.println("compile fail:\n" + res);
            session.disconnect();
            return;
        }

        // === 2. 编译成功，再跑 parallel ===
        ChannelExec ch2 = (ChannelExec) session.openChannel("exec");
        ch2.setCommand("cd /home/chao/work/test/java && " + cmd2);
        ch2.connect();

        // 把远程输出直接打到本机控制台
        ch2.setInputStream(null);
        ch2.setErrStream(System.err);
        try (InputStream in = ch2.getInputStream()) {
            in.transferTo(System.out);   // Java 9+，低版本自己写循环
        }
        ch2.disconnect();
        session.disconnect();
    }
}
