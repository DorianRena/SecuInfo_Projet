import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from  scanner import SimpleAntivirus

TEMPORARY_EXTENSIONS = ['.tmp', '.crdownload', '.part', '.download', '.swp']

class DownloadScanner(FileSystemEventHandler):
    def __init__(self):
        # Initialize scanner
        self.scanner = SimpleAntivirus()
        self.last_file = None
        
    def on_created(self, event):
        # Appelé au téléchargement
        if not event.is_directory:
            file_path = event.src_path
            print(f"Fichier détecté : {file_path}")

            if self.last_file == file_path:
                print(f"Fichier déjà traité : {file_path}")
                self.last_file = None
                return
            
            # Vérifier si le fichier est en téléchargement (nom temporaire)
            if not any(file_path.endswith(ext) for ext in TEMPORARY_EXTENSIONS):
                print(f"Le fichier a été renommé ou est complet : {file_path}")
                self.wait_for_file_end(file_path)

            self.last_file = file_path

    def wait_for_file_end(self, file_path):
        # Attendre que le fichier soit stable
        print(f"Vérification de la taille du fichier {file_path}...")

        initial_size = -1
        while True:
            try:
                current_size = os.path.getsize(file_path)
                if current_size == initial_size and current_size!=0:
                    print(f"Fichier en téléchargement détecté : {file_path}")
                    self.scanner.scan_file(file_path)
                    break
                else:
                    print(f"Le fichier est encore en téléchargement. Taille actuelle : {current_size} octets.")
                    initial_size = current_size
                    time.sleep(2)  # Vérifier toutes les 2 secondes
            except FileNotFoundError:
                print(f"Le fichier {file_path} n'est plus disponible. Il a peut-être été déplacé ou supprimé.")
                break

def find_downloads_dir():
    if os.path.exists(os.path.expanduser("~/Downloads")):
        return os.path.expanduser("~/Downloads")
    elif os.path.exists(os.path.expanduser("~/Téléchargements")):
        return os.path.expanduser("~/Téléchargements")
    else:
        return os.path.expanduser("~")


def main():
    # Répertoire à surveiller (par défaut, répertoire Téléchargements)
    downloads_dir = find_downloads_dir()
    if not os.path.exists(downloads_dir):
        print(f"Le répertoire {downloads_dir} n'existe pas.")
        return

    # Initialiser l'observateur et le gestionnaire d'événements
    event_handler = DownloadScanner()
    observer = Observer()
    observer.schedule(event_handler, downloads_dir, recursive=False)

    print(f"Surveillance du répertoire : {downloads_dir}")
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        print("Arrêt de la surveillance.")

    observer.join()

if __name__ == "__main__":
    main()
