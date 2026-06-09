use std::{collections::HashMap, os::fd::AsFd, path::PathBuf, rc::Rc, sync::mpsc};

use futures::future::join_all;
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

#[derive(Clone)]
pub struct FileLogSender {
    tx: mpsc::Sender<FileLogCommand>,
}

enum FileLogCommand {
    Write { path: PathBuf, msg: Vec<u8> },
    Invalidate,
}

impl FileLogSender {
    pub fn write(&self, path: PathBuf, msg: Vec<u8>) {
        let _ = self.tx.send(FileLogCommand::Write { path, msg });
    }

    pub fn invalidate(&self) {
        let _ = self.tx.send(FileLogCommand::Invalidate);
    }
}

pub fn spawn_file_logger() -> std::io::Result<FileLogSender> {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("file-logger".into())
        .spawn(move || run_file_logger(rx))
        .map_err(std::io::Error::other)?;
    Ok(FileLogSender { tx })
}

fn run_file_logger(rx: mpsc::Receiver<FileLogCommand>) {
    let mut urb = io_uring::IoUring::builder();
    urb.setup_single_issuer();
    let mut runtime = monoio::RuntimeBuilder::<monoio::IoUringDriver>::new()
        .uring_builder(urb)
        .build()
        .expect("zeroserve: failed to build file logger io_uring runtime");
    runtime.block_on(async move {
        let mut files = HashMap::<PathBuf, Rc<File>>::new();
        while let Ok(command) = rx.recv() {
            let mut commands = vec![command];
            while let Ok(command) = rx.try_recv() {
                commands.push(command);
            }

            let mut writes = Vec::new();
            for command in commands {
                match command {
                    FileLogCommand::Write { path, msg } => match cached_file(&mut files, path) {
                        Ok(file) => writes.push(async move { file.write_all_at(msg, 0).await.0 }),
                        Err(err) => eprintln!("file logger open failed: {err:?}"),
                    },
                    FileLogCommand::Invalidate => {
                        files.clear();
                    }
                }
            }
            for result in join_all(writes).await {
                if let Err(err) = result {
                    eprintln!("file logger write failed: {err:?}");
                }
            }
        }
    });
}

fn cached_file(files: &mut HashMap<PathBuf, Rc<File>>, path: PathBuf) -> std::io::Result<Rc<File>> {
    if let Some(file) = files.get(&path) {
        return Ok(file.clone());
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let file = Rc::new(File::from_std(file)?);
    files.insert(path, file.clone());
    Ok(file)
}
