use std::{os::fd::AsFd, rc::Rc};

use monoio::{buf::IoBuf, fs::File};

pub async fn async_log(msg: impl IoBuf) {
    thread_local! {
        static STDERR: Rc<File> = Rc::new(File::from_std(
            std::fs::File::from(
                std::io::stderr().as_fd().try_clone_to_owned()
                    .expect("failed to clone stderr")
            )).unwrap());
    }
    let stderr = STDERR.with(|x| x.clone());
    let _ = stderr.write_all_at(msg, 0).await;
}
