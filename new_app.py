from flask import Flask, request, render_template
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM
import torch
import subprocess
import os
import torch
from transformers import (
    T5ForConditionalGeneration, 
    T5Tokenizer, 
    Trainer, 
    TrainingArguments,
    DataCollatorForSeq2Seq
)
from torch.utils.data import Dataset
import json
app = Flask(__name__)
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
# Model yükle
model_path = "/home/red/Desktop/SDN/snort-rule-model"
tokenizer = AutoTokenizer.from_pretrained(model_path)
model = AutoModelForSeq2SeqLM.from_pretrained(model_path)

# Snort kural dosyası
RULE_FILE = "/tmp/snort/rules/local.rules"

class SnortRuleGenerator:
    def __init__(self, model_name="t5-small"):
        self.model_name = model_name
        self.tokenizer = T5Tokenizer.from_pretrained(model_name)
        self.model = T5ForConditionalGeneration.from_pretrained(model_name)
        self.device = device
        self.model.to(self.device)

        special_tokens = ["<snort>", "<rule>", "<alert>"]
        self.tokenizer.add_tokens(special_tokens)
        self.model.resize_token_embeddings(len(self.tokenizer))

    def prepare_data(self, data, test_size=0.3):
        data = replicate_critical_pairs(data)
        train_data, val_data = train_test_split(data, test_size=test_size, random_state=42)
        train_dataset = SnortRuleDataset(train_data, self.tokenizer)
        val_dataset = SnortRuleDataset(val_data, self.tokenizer)
        return train_dataset, val_dataset

    def train(self, train_dataset, val_dataset, output_dir="./snort-rule-model", num_epochs=10, batch_size=8, learning_rate=5e-5):
        training_args = TrainingArguments(
            output_dir=output_dir,
            num_train_epochs=num_epochs,
            per_device_train_batch_size=batch_size,
            per_device_eval_batch_size=batch_size,
            warmup_steps=50,
            weight_decay=0.01,
            logging_dir=f'{output_dir}/logs',
            logging_steps=10,
            evaluation_strategy="epoch",
            save_strategy="epoch",
            save_total_limit=2,
            load_best_model_at_end=True,
            metric_for_best_model="eval_loss",
            greater_is_better=False,
            learning_rate=learning_rate,
            fp16=True,
            dataloader_pin_memory=True,
            gradient_accumulation_steps=1
        )

        data_collator = DataCollatorForSeq2Seq(
            tokenizer=self.tokenizer,
            model=self.model,
            padding=True
        )

        trainer = Trainer(
            model=self.model,
            args=training_args,
            train_dataset=train_dataset,
            eval_dataset=val_dataset,
            data_collator=data_collator,
            tokenizer=self.tokenizer,
        )

        print("Starting training...")
        trainer.train()
        trainer.save_model()
        self.tokenizer.save_pretrained(output_dir)
        print(f"Model saved to {output_dir}")

    def generate_rule(self, input_text, max_length=256, num_beams=1, temperature=0.0):
        input_text = f"Generate Snort rule: {input_text.strip().lower()}"
        input_ids = self.tokenizer.encode(
            input_text,
            return_tensors="pt",
            max_length=128,
            truncation=True
        ).to(self.device)

        with torch.no_grad():
            outputs = self.model.generate(
                input_ids,
                max_length=max_length,
                num_beams=num_beams,
                temperature=temperature,
                do_sample=False,
                pad_token_id=self.tokenizer.pad_token_id,
                eos_token_id=self.tokenizer.eos_token_id,
                early_stopping=True
            )
        return self.tokenizer.decode(outputs[0], skip_special_tokens=True)

    def load_model(self, model_path):
        self.model = T5ForConditionalGeneration.from_pretrained(model_path)
        self.tokenizer = T5Tokenizer.from_pretrained(model_path)
        self.model.to(self.device)
        print(f"Model loaded from {model_path}")

def test_single_input(model_path, input_text):
    generator = SnortRuleGenerator()
    generator.load_model(model_path)

    result = generator.generate_rule(input_text)
    return result

with open("tr_eng.txt", "r", encoding="utf-8") as tr_eng:
    obj_list = [el.split(",") for el in tr_eng.readlines()]
def find_from_inputs(input:str):
    for el in obj_list:
        if input.strip().lower() == el[0].strip().lower():
            return el[1]

def generate_rule(input_text):
    inputs = tokenizer(input_text, return_tensors="pt", padding=True)
    outputs = model.generate(**inputs, max_length=150)
    rule = tokenizer.decode(outputs[0], skip_special_tokens=True)
    return rule.strip()

def append_rule_to_snort(rule):
    try:
        with open(RULE_FILE, "a") as f:
            f.write(rule + "\n")
        subprocess.run(["sudo", "systemctl", "restart", "snort"], check=True)
        return True, "Snort yeniden başlatıldı, kural eklendi."
    except Exception as e:
        return False, f"Hata: {str(e)}"

@app.route("/", methods=["GET", "POST"])
def index():
    user_input = ""
    rule_output = ""
    system_response = ""
    if request.method == "POST":
        user_input = request.form.get("user_input", "")
        if user_input.strip():
            rule_output = test_single_input(model_path, find_from_inputs(user_input)).replace(" > ", " <> ")
            success, system_response = append_rule_to_snort(rule_output)
    return render_template("index.html", input=user_input, output=rule_output, response=system_response)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
